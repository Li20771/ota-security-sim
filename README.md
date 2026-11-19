# ota-security-sim

> **定位**：纯标准库 OTA 升级安全仿真核心（更新服务器 + 目标 ECU + 校验链 + 缺陷对照组）
> **技能**：OTA 安全机制、签名/哈希/防降级、pytest 矩阵
> **证据**：13 passed（2026-11-12 本机复跑；无历史证据包——如实声明）
> **复现**：`python -m pytest -q`
> **边界**：仿真；HMAC 为教学实现；TARA/报告见 vehicle-security-practice
> **维护**：稳定（MIT）


纯标准库实现的 OTA 升级安全**仿真核心**：模拟更新服务器 + 模拟目标 ECU，包含「下载 → 清单完整性 → 签名 → 哈希 → 防降级 → 安装」完整校验链，每个安全控制都有可参数化的「缺陷开关」用于构造对照组。零硬件、零第三方运行时依赖。

> 定位声明：本项目用于**教学与仿真环境**中的 OTA 安全机制测试练习，不针对、也不适用于任何真实车辆、真实 ECU 或任何产品。签名模型为 HMAC-SHA256 教学级实现；真实产品应使用非对称签名（接口已按 manifest + signature 形态预留）。

## 解决什么问题

如何在没有真实 OTA 系统的情况下，练习并验证升级链路的四类安全控制：

- **来源真实性**：清单签名校验（错密钥伪造 / 未签名清单 → 拒绝）
- **完整性**：包体哈希与清单比对（中间替换包 → 拒绝）
- **版本单调（防降级/防回滚）**：降级与同版重装 → 拒绝；关闭该控制则旧版本包可装入（对照组）
- **异常路径**：清单在而包体 404（CDN 不一致）→ FAILED 而非静默；非法版本号 → ValueError
- **缺陷对照组**：每个控制都可一键关闭（`verify_sig=False` / `verify_hash=False` / `anti_downgrade=False` / `serve_wrong_hash=True`），用例同时断言「开着拒绝、关了放行」——即缺陷的可观测后果

## 快速开始

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

## 目录结构

```text
ota-security-sim/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── ota_sim/
│   ├── __init__.py
│   └── core.py           # UpdateServer（可注入攻击面）+ TargetEcu（可关闭的校验链）+ HMAC 签名
└── tests/
    ├── conftest.py       # 让 tests/ 找到 ota_sim/（不要求安装为包）
    └── test_ota_matrix.py # 13 条测试矩阵用例（正向/签名/完整性/防降级/异常/缺陷对照）
```

## 证据

- 本仓库**未附带**历史运行证据包（源项目执行时未按 RUN 目录归档 JUnit 结果，为诚实起见不引用任何无法复核的数字）。
- **本机复跑记录**（2026-11-12，pytest 9.2.0 / Python 3.12.0，Windows）：`python -m pytest -q` → **13 passed in 0.03s**，退出码 0。
- 说明：源笔记将本批矩阵记为「14 条」，实际 pytest 收集为 **13 条**（`test_malformed_version_rejected` 为单条含 3 个断言）——以实际收集数为准。

## Status

- **已实现**：仿真核心（`ota_sim/core.py`）与 13 条测试矩阵用例，覆盖签名/完整性/防降级/异常路径/缺陷对照组。
- **未完成**：TARA 威胁分析、端到端架构图、完整测试报告、A/B 分区与断电回退模拟、UDS 刷写（0x34/0x36/0x37）链路——均未实现。

## License

MIT（见 LICENSE）。

---

**English TL;DR:** A pure-stdlib OTA update security simulation core (mock update server + mock target ECU) with a full verification chain — manifest integrity, signature, hash, anti-downgrade — where every control has a switchable "defect mode" for building control groups, plus 13 pytest matrix cases. Re-run locally on 2026-11-12: 13 passed / 0 failed. No historical evidence pack is bundled (none was archived). TARA, architecture diagrams, full report, A/B partition and UDS flashing are not implemented. Simulation only — not applicable to real vehicles.
