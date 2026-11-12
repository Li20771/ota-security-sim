"""P16 OTA 模拟核心：可参数化的更新服务器与目标 ECU（纯标准库，零硬件）。

签名模型：HMAC-SHA256（密钥分发给 ECU）——教学级强度，演示「来源验证/完整性/
防降级」三类控制如何被测试；真实产品应换非对称签名（SM2/RSA），接口已按
「manifest + signature」形态预留。

清单（manifest）结构：
    {"version": "2.0.0", "size": 123, "sha256": "...", "sig": "hmac-hex"}
判定顺序（与 11/04-OTA升级流程与安全测试.md 的测试矩阵一致）：
    下载 → 清单完整性 → 签名 → 哈希 → 版本单调（防降级）→ 安装
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

# ---------------------------------------------------------------- 工具
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def version_tuple(v: str) -> tuple[int, ...]:
    """'2.10.3' → (2, 10, 3)；非法版本抛 ValueError（比静默 0 安全）。"""
    if not VERSION_RE.match(v or ""):
        raise ValueError(f"非法版本号: {v!r}")
    return tuple(int(x) for x in v.split("."))


def sign_manifest(manifest: dict, key: bytes) -> str:
    """HMAC-SHA256 对清单的规范化 JSON 签名（去掉 sig 字段本身）。"""
    core = {k: v for k, v in manifest.items() if k != "sig"}
    blob = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, blob, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- 服务器
class UpdateServer:
    """模拟 OTA 云端：版本库 + 签发清单 + 可注入的攻击面。

    可参数化（测试矩阵的输入旋钮）：
        sign_key=None        → 不签名（演示"无签名验证"缺陷形态）
        serve_wrong_hash     → 清单哈希与包体不一致（演示"包被篡改"）
        serve_downgrade      → 对降级请求返回旧版本包（演示"无防降级"形态）
    """

    def __init__(self, key: bytes | None = b"ota-demo-key",
                 serve_wrong_hash: bool = False,
                 serve_downgrade: bool = False) -> None:
        self.packages: dict[str, bytes] = {}      # version → payload
        self.sign_key = key
        self.serve_wrong_hash = serve_wrong_hash
        self.serve_downgrade = serve_downgrade

    def publish(self, version: str, payload: bytes) -> None:
        if not VERSION_RE.match(version):
            raise ValueError(f"非法版本号: {version!r}")
        self.packages[version] = payload

    def manifest_for(self, version: str) -> dict | None:
        """签发某版本清单；serve_downgrade=True 时旧版本也照常发布（缺陷形态）。"""
        if version not in self.packages:
            return None
        payload = self.packages[version]
        manifest = {
            "version": version,
            "size": len(payload),
            "sha256": (
                hashlib.sha256(b"TAMPERED").hexdigest()          # 攻击旋钮：错哈希
                if self.serve_wrong_hash
                else hashlib.sha256(payload).hexdigest()
            ),
        }
        if self.sign_key:
            manifest["sig"] = sign_manifest(manifest, self.sign_key)
        return manifest

    def payload_for(self, version: str) -> bytes | None:
        return self.packages.get(version)


# ---------------------------------------------------------------- 目标 ECU
class TargetEcu:
    """模拟目标 ECU：下载 → 校验 → 防降级 → A/B 安装。

    可参数化（安全配置旋钮，用于构造"缺陷形态"对照组）：
        verify_sig=False     → 不验签（缺陷：来源不可信）
        verify_hash=False    → 不验哈希（缺陷：完整性不校验）
        anti_downgrade=False → 无防降级（缺陷：可回滚到旧版本）
    """

    def __init__(self, key: bytes | None = b"ota-demo-key", *,
                 verify_sig: bool = True,
                 verify_hash: bool = True,
                 anti_downgrade: bool = True,
                 current_version: str = "1.0.0") -> None:
        self.key = key
        self.verify_sig = verify_sig
        self.verify_hash = verify_hash
        self.anti_downgrade = anti_downgrade
        self.version = current_version
        self.slots: dict[str, bytes] = {}          # 已安装的版本 → 包体
        self.log: list[str] = []

    # ------------------------------------------------------------ 校验链
    def _check_manifest(self, manifest: dict) -> str | None:
        """返回拒绝原因；None = 通过。判定顺序即测试矩阵的判定顺序。"""
        for field in ("version", "size", "sha256"):
            if field not in manifest:
                return f"清单缺字段 {field}（N/A：结构不完整）"
        if not VERSION_RE.match(manifest["version"]):
            return "清单版本号非法"
        if self.verify_sig:
            if "sig" not in manifest:
                return "清单未签名（来源不可信）"
            expect = sign_manifest(manifest, self.key or b"")
            if not hmac.compare_digest(expect, manifest["sig"]):
                return "签名校验失败（密钥不匹配或清单被篡改）"
        return None

    def _check_downgrade(self, new_version: str) -> str | None:
        if not self.anti_downgrade:
            return None                             # 缺陷形态：无防降级
        if version_tuple(new_version) <= version_tuple(self.version):
            return f"拒绝降级/同版重装：{self.version} → {new_version}"
        return None

    # ------------------------------------------------------------ 更新流程
    def update(self, server: UpdateServer, want_version: str | None = None) -> dict:
        """完整更新流程。返回结果字典：status / detail / installed。"""
        result = {"status": None, "detail": "", "installed": False}

        # ① 取清单（want=None 时接受服务器提供的最新版——含降级包，视服务器旋钮）
        manifest = server.manifest_for(want_version) if want_version else None
        if manifest is None and want_version is None:
            candidates = sorted(server.packages, key=version_tuple, reverse=True)
            manifest = server.manifest_for(candidates[0]) if candidates else None
        if manifest is None:
            result.update(status="REJECTED", detail="服务器无此版本（404）")
            self.log.append(result["detail"])
            return result

        # ② 清单完整性 + 签名
        if (reason := self._check_manifest(manifest)) is not None:
            result.update(status="REJECTED", detail=reason)
            self.log.append(reason)
            return result
        version = manifest["version"]

        # ③ 防降级
        if (reason := self._check_downgrade(version)) is not None:
            result.update(status="REJECTED", detail=reason)
            self.log.append(reason)
            return result

        # ④ 下载 + 哈希
        payload = server.payload_for(version)
        if payload is None:
            result.update(status="FAILED", detail="包体 404（清单在、包不在）")
            self.log.append(result["detail"])
            return result
        if self.verify_hash:
            actual = hashlib.sha256(payload).hexdigest()
            if actual != manifest["sha256"]:
                result.update(status="REJECTED", detail=f"哈希不匹配（{actual[:12]}…）")
                self.log.append(result["detail"])
                return result

        # ⑤ 安装（A/B 记账 + 版本推进）
        self.slots[version] = payload
        self.version = version
        result.update(status="INSTALLED", installed=True, detail=f"已安装 {version}")
        self.log.append(result["detail"])
        return result
