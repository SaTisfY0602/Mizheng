"""成员三提供的集中 ID 分配器。

协作规范 §3.6 约定：项目、材料、候选、事实、快照、判定、事件、报告和证据包的
ID 统一由 ``IdAllocator.allocate(prefix, project_id)`` 生成，解析器先申请 ID，
不自行生成可能冲突的正式 ID。样例中的短 ID（``DEC-001``）只供阅读，不规定生产
编号格式。

设计取舍
--------
* **确定性**：同一实例按固定调用顺序产生固定序列，因此「相同输入 + 新实例」
  可以逐字节复现整条流程的产物（技术栈与版本管理方案 §5 的可复现性要求）。
* **实例内唯一**：``(prefix, project_id)`` 各自独立计数，不同前缀不会互相挤占。
* **跨运行唯一（可选）**：传入 ``run_token`` 时把令牌编入 ID，便于区分多次运行的
  产物；默认不传，保证 9 月 28 日演示与回归测试可稳定复现。
* 测试按语义和引用关系比对，不依赖生成次序（协作规范 §3.6）。
"""

from __future__ import annotations

import re
import threading

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class IdAllocatorError(ValueError):
    """前缀、项目号或运行令牌不合法，无法生成稳定 ID。"""


class IdAllocator:
    """线程安全的确定性 ID 分配器，实现 ``mvp_contracts.interfaces.IdAllocator``。"""

    def __init__(self, *, run_token: str | None = None) -> None:
        if run_token is not None:
            require_identifier(run_token, "run_token")
        self._run_token = run_token
        self._counters: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def allocate(self, *, prefix: str, project_id: str) -> str:
        """为 ``prefix`` 类对象分配一个正式 ID，形如 ``DEC-PRJ-001-0001``。"""
        normalized_prefix = require_identifier(prefix, "prefix").upper()
        normalized_project = require_identifier(project_id, "project_id")
        with self._lock:
            key = (normalized_prefix, normalized_project)
            sequence = self._counters.get(key, 0) + 1
            self._counters[key] = sequence

        parts = [normalized_prefix, normalized_project]
        if self._run_token is not None:
            parts.append(self._run_token)
        parts.append(f"{sequence:04d}")
        return "-".join(parts)

    def issued_count(self, *, prefix: str, project_id: str) -> int:
        """已为某个 ``(prefix, project_id)`` 组合发出的 ID 数量，供测试与审计使用。"""
        normalized_prefix = require_identifier(prefix, "prefix").upper()
        normalized_project = require_identifier(project_id, "project_id")
        with self._lock:
            return self._counters.get((normalized_prefix, normalized_project), 0)


def require_identifier(value: str, field: str) -> str:
    """校验标识只含字母、数字、下划线和连字符，且以字母或数字开头。

    受控材料存储层（``mvp_flow.storage``）复用这一份校验，保证 ID 与
    ``storage_key`` 片段的取值范围一致。
    """
    if not isinstance(value, str) or not value or not _TOKEN_PATTERN.fullmatch(value):
        raise IdAllocatorError(
            f"{field} 必须是以字母或数字开头的非空标识（允许字母、数字、下划线、连字符）：{value!r}"
        )
    return value
