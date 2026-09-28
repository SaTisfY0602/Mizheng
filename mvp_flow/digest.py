"""SM3 摘要工具。

与成员二核验器使用同一实现（``hashlib.new("sm3")``，分块读取），保证导出端和
核验端对同一文件算出同一摘要。不使用 SHA-256，也不接受样例中的虚构摘要。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024  # 1 MiB，与 mvp_decision.verifier 保持一致


def sm3_of_bytes(data: bytes) -> str:
    """返回字节串的小写 64 位 SM3 十六进制摘要。"""
    digest = hashlib.new("sm3")
    digest.update(data)
    return digest.hexdigest()


def sm3_of_file(path: Path) -> str:
    """分块计算文件真实 SM3，避免把大文件整体读入内存。"""
    digest = hashlib.new("sm3")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
