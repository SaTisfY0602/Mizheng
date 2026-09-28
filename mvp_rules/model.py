"""规则包的内存模型：标准指标目录与规则清单的只读视图。

规则包刻意**不放进共享契约**（``mvp_contracts.models``）。共享契约描述的是
「证据 → 判定」的跨模块交接对象，而规则包是**版本化的内容库**：它记录标准指标
定位、当前已实现的规则，以及每条规则的来源与测试依据。等下一阶段确实需要把规则
包当成交接对象时，再按协作规范 §6.1 连同共享类、样例与测试一起升级契约版本。

术语约定（对应实现方案 §7.4.2 与 §7.4.3）：

* **标准指标项**：来自 GB/T 39786-2021 的条款定位，例如 ``NET-AUTH`` 属于第 7.2 节
  「网络和通信安全」。
* **辅助核查单元**：``U01``—``U16``，是工具内部单元编号，**不是**国家标准条款编号。
* **自动规则**：真正在程序里执行的规则，``rule_id`` 形如 ``RISK-*`` / ``DEC-*``。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class Indicator:
    """标准指标目录中的一项（实现方案 §7.4.1 第一层内容库）。"""

    indicator_id: str
    standard: str
    clause: str
    title: str
    domain: str
    levels: tuple[int, ...]
    assessment_object: str
    required_materials: tuple[str, ...]
    check_method: str
    automated_rule_ids: tuple[str, ...]
    level_clauses: Mapping[str, str] = field(default_factory=dict)
    note: str = ""

    @property
    def automated(self) -> bool:
        """是否至少有一条已实现的自动规则覆盖它。"""
        return bool(self.automated_rule_ids)


@dataclass(frozen=True)
class RuleSpec:
    """一条可在程序中执行的规则（实现方案 §7.4.1 第二层内容库）。"""

    rule_id: str
    pack: str
    title: str
    layer: str
    indicator_id: str
    tool_unit: str
    evaluation: str
    engine_entry: str
    condition: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    standard_refs: tuple[str, ...] = ()
    tested_by: tuple[str, ...] = ()

    @property
    def severity(self) -> str | None:
        """风险规则的等级；判定规则没有等级。"""
        value = self.parameters.get("severity")
        return str(value) if value is not None else None


@dataclass(frozen=True)
class PackMeta:
    """规则包本身的版本信息。

    ``version`` 是当前生效的规则版本；``supersedes`` 记录本包接替的历史版本号。
    判定引擎只要求快照的 ``rule_version`` 属于 :meth:`RuleSet.accepted_versions`：
    这样既让真实解析链路继续沿用材料里既有的版本号，又能让引用历史版本的契约样例
    照常核验，而不必为了跑通而伪造样例数据。
    """

    id: str
    version: str
    schema: str
    description: str
    created_at: str
    supersedes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleSet:
    """一个完整规则包：元信息 + 标准指标目录 + 规则清单 + 版本→规则映射。"""

    meta: PackMeta
    indicators: tuple[Indicator, ...]
    rules: tuple[RuleSpec, ...]
    rule_versions: Mapping[str, tuple[str, ...]]
    source_dir: Path

    # --- 查询接口 ---------------------------------------------------------
    def rule(self, rule_id: str) -> RuleSpec:
        """按 ``rule_id`` 取规则；不存在即报错，不返回 ``None`` 让调用方猜。"""
        for spec in self.rules:
            if spec.rule_id == rule_id:
                return spec
        raise KeyError(f"规则包中不存在规则 {rule_id!r}")

    def has_rule(self, rule_id: str) -> bool:
        return any(spec.rule_id == rule_id for spec in self.rules)

    def rule_ids(self, *, pack: str | None = None, layer: str | None = None) -> tuple[str, ...]:
        return tuple(
            spec.rule_id
            for spec in self.rules
            if (pack is None or spec.pack == pack) and (layer is None or spec.layer == layer)
        )

    def indicator(self, indicator_id: str) -> Indicator:
        for item in self.indicators:
            if item.indicator_id == indicator_id:
                return item
        raise KeyError(f"指标目录中不存在指标 {indicator_id!r}")

    def severity_of(self, rule_id: str) -> str:
        """风险规则等级；取不到即报错，避免静默用默认值。"""
        severity = self.rule(rule_id).severity
        if severity is None:
            raise KeyError(f"规则 {rule_id!r} 未定义 severity 参数")
        return severity

    def param(self, rule_id: str, name: str) -> Any:
        spec = self.rule(rule_id)
        if name not in spec.parameters:
            raise KeyError(f"规则 {rule_id!r} 未定义参数 {name!r}")
        return spec.parameters[name]

    def int_param(self, rule_id: str, name: str) -> int:
        value = self.param(rule_id, name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"规则 {rule_id!r} 的参数 {name!r} 必须是整数，实际为 {value!r}")
        return value

    def str_tuple_param(self, rule_id: str, name: str) -> tuple[str, ...]:
        value = self.param(rule_id, name)
        if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
            raise TypeError(f"规则 {rule_id!r} 的参数 {name!r} 必须是字符串列表，实际为 {value!r}")
        return tuple(value)

    def mapping_param(self, rule_id: str, name: str) -> Mapping[str, str]:
        value = self.param(rule_id, name)
        if not isinstance(value, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        ):
            raise TypeError(f"规则 {rule_id!r} 的参数 {name!r} 必须是字符串映射，实际为 {value!r}")
        return MappingProxyType(dict(value))

    @property
    def accepted_versions(self) -> frozenset[str]:
        """判定引擎接受的快照 ``rule_version``。

        由「当前版本 + 接替的历史版本 + 显式声明过规则集的版本」三者并集构成，
        保证 :meth:`rules_for_version` 对每个被接受的版本都有明确答案。
        """
        return frozenset(
            {self.meta.version, *self.meta.supersedes, *self.rule_versions.keys()}
        )

    def rules_for_version(self, rule_version: str) -> tuple[str, ...]:
        """某个快照规则版本允许跑的判定规则 ID。

        显式声明优先；否则回退到规则包声明的全部 DECISION 层规则。回退是有意的：
        版本号比规则包新时按最新规则跑，而不是静默不跑任何规则。
        """
        declared = self.rule_versions.get(rule_version)
        if declared is not None:
            return declared
        return self.rule_ids(layer="DECISION")
