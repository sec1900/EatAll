"""Shannon 熵工具单测。"""
import base64
import os

from decoders.shannon import (
    HIGH_ENTROPY_THRESHOLD,
    MIN_DYNAMIC_LEN,
    is_high_entropy,
    is_high_entropy_str,
    shannon_entropy,
)


def test_entropy_constants():
    assert shannon_entropy(b"") == 0.0
    # 全同字节 → 熵 0
    assert shannon_entropy(b"A" * 100) == 0.0
    # 随机 1024 字节 → 接近 8
    rand = os.urandom(1024)
    e = shannon_entropy(rand)
    assert e > 7.0


def test_is_high_entropy():
    # 8 个不同字节：log2(8)=3.0 < 4.5 → 不高熵
    assert not is_high_entropy(bytes(range(8)))
    # 64 字节伪随机 → 高熵
    assert is_high_entropy(os.urandom(64))
    # 长度不足
    assert not is_high_entropy(os.urandom(4))
    # 字符串版（32 个不同字符 → 熵 log2(32)=5.0 > 4.5；注意 latin-1 控制字符经
    # UTF-8 replace 会坍缩成 '?'，不能用于熵判定）
    assert is_high_entropy_str("X9q2K7v4M1z8P3w6T5r0S7n2AbCdEfGh")
    assert not is_high_entropy_str("hello world hello world")


def test_threshold_value():
    assert HIGH_ENTROPY_THRESHOLD == 4.5
    assert MIN_DYNAMIC_LEN == 8
