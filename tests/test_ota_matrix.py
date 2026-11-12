"""P16 OTA 测试矩阵（第一批 14 条）——每条 = 矩阵一行，含前置/操作/预期。

判定顺序与被测实现一致（11/04-OTA升级流程与安全测试.md）：
    下载 → 清单完整性 → 签名 → 哈希 → 版本单调（防降级）→ 安装
"""
from __future__ import annotations

import pytest

from ota_sim.core import TargetEcu, UpdateServer, sign_manifest, version_tuple

KEY = b"ota-demo-key"


def make_server(**kw) -> UpdateServer:
    s = UpdateServer(key=kw.pop("key", KEY), **kw)
    s.publish("1.0.0", b"firmware-v1")
    s.publish("2.0.0", b"firmware-v2-official")
    s.publish("2.1.0", b"firmware-v21-official")
    return s


def make_ecu(**kw) -> TargetEcu:
    kw.setdefault("current_version", "1.0.0")
    return TargetEcu(key=KEY, **kw)


# ================================================================ 正向
def test_valid_update_installs():
    """正常升级：1.0.0 → 2.0.0，版本推进且包体落槽。"""
    ecu, server = make_ecu(), make_server()
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "INSTALLED" and r["installed"]
    assert ecu.version == "2.0.0"
    assert ecu.slots["2.0.0"] == b"firmware-v2-official"


def test_manifest_signature_roundtrip():
    """清单签名可复算：同清单同密钥 → 同签名（确定性）。"""
    m = {"version": "3.0.0", "size": 3, "sha256": "aa" * 32}
    assert sign_manifest(m, KEY) == sign_manifest(m, KEY)


# ================================================================ 签名
def test_forged_signature_rejected():
    """伪造清单（错密钥签名）→ 拒绝：『签名校验失败』。"""
    ecu, server = make_ecu(), make_server(key=b"attacker-key")
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "REJECTED" and "签名" in r["detail"]


def test_unsigned_manifest_rejected_when_verification_on():
    """无签名清单 + 开启验签 → 拒绝：来源不可信。"""
    ecu, server = make_ecu(), UpdateServer(key=None)
    server.publish("2.0.0", b"firmware-v2")
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "REJECTED" and "未签名" in r["detail"]


# ================================================================ 完整性
def test_tampered_package_rejected():
    """包被篡改（清单哈希与包体不一致）→ 拒绝：『哈希不匹配』。"""
    ecu = make_ecu()
    server = make_server(serve_wrong_hash=True)      # 攻击旋钮：清单哈希错
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "REJECTED" and "哈希不匹配" in r["detail"]
    assert ecu.version == "1.0.0"                    # 版本不得推进


# ================================================================ 防降级
def test_downgrade_rejected_with_anti_downgrade():
    """有防降级：2.1.0 → 请求装 2.0.0 → 拒绝。"""
    ecu = make_ecu(current_version="2.1.0")
    server = make_server()
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "REJECTED" and "拒绝降级" in r["detail"]
    assert ecu.version == "2.1.0"


def test_downgrade_possible_when_disabled():
    """缺陷对照组：关闭防降级 → 降级成功（这就是缺失该机制的后果）。"""
    ecu = make_ecu(current_version="2.1.0", anti_downgrade=False)
    server = make_server()
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "INSTALLED" and ecu.version == "2.0.0"


def test_same_version_reinstall_rejected():
    """同版重装也按降级拒绝（版本单调性包含相等）。"""
    ecu = make_ecu(current_version="2.0.0")
    server = make_server()
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "REJECTED"


# ================================================================ 异常路径
def test_payload_missing_after_manifest_404():
    """清单签发后、下载前包被撤（模拟 CDN 不一致）→ FAILED，非静默。"""
    import hashlib

    ecu, server = make_ecu(), make_server()
    server.publish("9.9.9", b"x")
    # 子类：清单照常签发（绕过 manifest_for 的包存在性检查），模拟"清单已推送、包已撤"
    class CDN(UpdateServer):
        def manifest_for(self, v):
            m = {"version": v, "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
            m["sig"] = sign_manifest(m, KEY)
            return m

    r = ecu.update(CDN(), "9.9.9")
    assert r["status"] == "FAILED" and "404" in r["detail"]


def test_unknown_version_404():
    """请求不存在的版本 → REJECTED（404）。"""
    ecu, server = make_ecu(), make_server()
    r = ecu.update(server, "8.8.8")
    assert r["status"] == "REJECTED" and "404" in r["detail"]


def test_malformed_version_rejected():
    """非法版本号（'2.0' 两位）→ ValueError，而非静默安装。"""
    server = make_server()
    with pytest.raises(ValueError):
        server.publish("2.0", b"x")
    with pytest.raises(ValueError):
        version_tuple("2.0")
    with pytest.raises(ValueError):
        version_tuple("")


# ================================================================ 缺陷对照组
def test_no_hash_verification_accepts_tampered():
    """缺陷对照组：关闭哈希校验 + 篡改包体（清单哈希不一致被跳过）→ 恶意包被静默安装。"""
    ecu = make_ecu(verify_hash=False)
    server = make_server(serve_wrong_hash=True)      # 清单哈希错（反正会被跳过）
    server.packages["2.0.0"] = b"MALICIOUS-PAYLOAD"  # 攻击者替换包体
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "INSTALLED" and ecu.version == "2.0.0"
    assert ecu.slots["2.0.0"] == b"MALICIOUS-PAYLOAD"      # 恶意包真的装进去了


def test_no_sig_verification_accepts_forged():
    """缺陷对照组：关闭验签 + 攻击者签发 → 伪造包被安装。"""
    ecu = make_ecu(verify_sig=False)
    server = make_server(key=b"attacker-key")
    r = ecu.update(server, "2.0.0")
    assert r["status"] == "INSTALLED"
