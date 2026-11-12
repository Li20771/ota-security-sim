"""P16 测试路径：让 tests/ 找到 ota_sim/（不要求安装为包）。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
