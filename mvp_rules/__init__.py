"""版本化规则包：标准指标目录 + 已实现规则清单。

本模块解决「规则版本要能回溯到具体实验」这条要求：弱算法名单、协议黑名单、
密钥长度下限、临期天数等口径不再散落在代码里，而是集中在本包的 JSON 数据中，
带版本号、带 SM3 摘要，并由 :func:`load_rule_set` 做静态一致性校验。

```text
mvp_rules/data/
  meta（id/version/schema） + indicators（标准指标目录） + rules（规则清单）
        ↓ load_rule_set()  严格校验：引用、重复、层级、单元编号
      RuleSet  —— 只读视图，供 mvp_risk 与 mvp_decision 查询
        ↓ rule_pack_sm3()  按文件名排序对全部规则文件求 SM3
      RulePack.sm3 —— 写进共享契约，核验端可复核规则内容是否被改动
```

**规则包不放进共享契约**：它是内容库，不是跨模块交接对象。``RulePack`` 仍然是
共享契约里那个 ``{id, version, sm3, rule_ids}``。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .loader import DATA_DIR, LAYERS, TOOL_UNITS, RulePackError, load_rule_set
from .model import Indicator, PackMeta, RuleSet, RuleSpec

__all__ = [
    "DATA_DIR",
    "LAYERS",
    "TOOL_UNITS",
    "Indicator",
    "PackMeta",
    "RulePackError",
    "RuleSet",
    "RuleSpec",
    "default_rule_set",
    "load_rule_set",
    "rule_pack_sm3",
]

_CACHED: RuleSet | None = None


def default_rule_set() -> RuleSet:
    """加载随代码分发的默认规则包（进程内缓存一次）。

    规则包是随代码发布的只读内容，进程内不会变化；缓存避免每个对象、每条规则
    都重读一遍 JSON。需要别的版本时显式调用 :func:`load_rule_set`。
    """
    global _CACHED
    if _CACHED is None:
        _CACHED = load_rule_set(DATA_DIR)
    return _CACHED


def _normalized(path: Path) -> bytes:
    """读取规则文件字节，并把行尾统一成 LF。

    这一步不是洁癖，是**正确性**要求：git 的 ``text=auto`` 会在提交时做行尾转换，
    所以同一个文件在不同机器的工作区里可能是 CRLF 或 LF，直接对原始字节求摘要会
    得到不同结果 —— 那 ``rule_sm3`` 就失去了「跨机器可比」的意义，核验端会误报
    「规则已被改动」。

    规范化后，摘要只取决于规则**内容**，与谁在什么平台上检出无关。
    """
    return path.read_bytes().replace(b"\r\n", b"\n")


def rule_pack_sm3(rule_set: RuleSet | None = None) -> str:
    """对规则包的全部数据文件求小写 64 位 SM3。

    按文件名排序后把「文件名 + 内容」依次喂进同一个 SM3 上下文，因此结果只取决于
    规则内容本身，与文件系统返回顺序、行尾风格都无关（行尾已规范化）。导出端与
    核验端用它对同一版本比对。
    """
    active = rule_set if rule_set is not None else default_rule_set()
    digest = hashlib.new("sm3")
    for path in sorted(active.source_dir.glob("*.json"), key=lambda item: item.name):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_normalized(path))
    return digest.hexdigest()
