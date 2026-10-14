"""信息熵工具：Shannon 熵计算与高熵（动态值）判定。

解码器与 POC 重建共用的地基模块：
- 高熵串（Shannon > 4.5 且 >= 8B）被识别为动态值（随机 token、盐、session id……），
  在归一化/模板化时替换为 {dyn} / {{randstr}} 占位符。
"""
from __future__ import annotations

import math

# 高熵判定阈值（bits/byte，8 为完全随机）
HIGH_ENTROPY_THRESHOLD = 4.5
# 高熵串最短字节长度
MIN_DYNAMIC_LEN = 8


def shannon_entropy(data: bytes) -> float:
    """计算字节串的 Shannon 熵（0 ~ 8 bits/byte）。空串返回 0.0。"""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_high_entropy(data: bytes) -> bool:
    """字节串是否属于高熵动态值（Shannon > 4.5 且长度 >= 8B）。"""
    return len(data) >= MIN_DYNAMIC_LEN and shannon_entropy(data) > HIGH_ENTROPY_THRESHOLD


def is_high_entropy_str(s: str) -> bool:
    """字符串版 is_high_entropy（UTF-8 编码后判定）。"""
    return is_high_entropy(s.encode("utf-8", "replace"))
