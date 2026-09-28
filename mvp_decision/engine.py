"""判定引擎：把各条判定规则的条件结果组装成共享 ``Decision`` 对象。

判定规则按 ``rule_pack.rule_ids`` 决定跑哪些，规则实现从 :data:`RULE_REGISTRY` 查找。
加一条规则只需在本文件注册「规则 ID → 条件求值器 + 结论映射」，不必改调用方；这样
风险侧积累的经验可以逐条迁到符合性判定，而不必每次重写引擎。

本模块**不重新实现条件逻辑**：``binding`` / ``certificate_time`` 复用
:func:`mvp_decision.rules.evaluate_demo_bind_time`，密钥强度与证书用途复用
:mod:`mvp_decision.rules` 里的条件求值器，以保证同一份证据在判定与风险两侧得到
一致的口径。

证据包、核验器、报告与通用规则语言不在本模块范围内。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import (
    ConditionState,
    Decision,
    EvidenceSnapshot,
    Outcome,
    RulePack,
    WorkflowStatus,
)
from mvp_rules import default_rule_set

from .rules import (
    BINDING,
    CERTIFICATE_TIME,
    EXTENDED_KEY_USAGE,
    KEY_STRENGTH,
    KEY_USAGE,
    RULE_KEY_STRENGTH,
    RULE_KEY_USAGE,
    EvaluatedConditions,
    evaluate_certificate_key_strength,
    evaluate_certificate_purpose,
    evaluate_demo_bind_time,
)

RULE_ID = "DEMO-BIND-TIME"
RULE_ID_BIND_TIME = "DEC-BIND-TIME"
DECISION_ID_PREFIX = "DEC"

#: 条件求值器签名：``(snapshot, object_id) -> EvaluatedConditions``
ConditionEvaluator = Callable[[EvidenceSnapshot, str], EvaluatedConditions]


class DecisionEngineError(Exception):
    """判定引擎无法产出符合契约的判定时抛出。"""


class RulePackError(DecisionEngineError):
    """规则包版本或内容不受支持。"""


@dataclass(frozen=True)
class RuleDefinition:
    """一条判定规则：条件求值器 + 结论映射 + 条件摘要。"""

    rule_id: str
    evaluate_conditions: ConditionEvaluator
    map_outcome: Callable[[EvaluatedConditions, str], tuple[list[Outcome], Outcome | None, WorkflowStatus]]
    conditions: tuple[str, ...]


def _map_bind_time(
    result: EvaluatedConditions, object_id: str
) -> tuple[list[Outcome], Outcome | None, WorkflowStatus]:
    """绑定 + 证书有效期：沿用演示规则既有口径。"""
    return _map_outcome(result.states, result.gap_ids, object_id)


def _conditions_from_demo(
    snapshot: EvidenceSnapshot, object_id: str
) -> EvaluatedConditions:
    """适配演示规则的元组返回，使其与其它条件求值器同形。"""
    states, support_fact_ids, gap_ids = evaluate_demo_bind_time(snapshot, object_id)
    return EvaluatedConditions(
        states=states, support_fact_ids=support_fact_ids, gap_ids=gap_ids
    )


def _map_key_strength(
    result: EvaluatedConditions, object_id: str
) -> tuple[list[Outcome], Outcome | None, WorkflowStatus]:
    if result.states[BINDING] is ConditionState.UNKNOWN:
        return _pending_binding(result, object_id)
    state = result.states[KEY_STRENGTH]
    if state is ConditionState.REFUTED:
        # 密钥强度不足是明确的否定结论：口径来自规则包阈值，不是临时解释。
        return [Outcome.NON_COMPLIANT], Outcome.NON_COMPLIANT, WorkflowStatus.EVALUATED
    if state is ConditionState.SUPPORTED:
        return [Outcome.COMPLIANT], Outcome.COMPLIANT, WorkflowStatus.EVALUATED
    return _pending_condition(result, object_id, KEY_STRENGTH)


def _map_key_usage(
    result: EvaluatedConditions, object_id: str
) -> tuple[list[Outcome], Outcome | None, WorkflowStatus]:
    if result.states[BINDING] is ConditionState.UNKNOWN:
        return _pending_binding(result, object_id)
    relevant = [result.states[KEY_USAGE], result.states[EXTENDED_KEY_USAGE]]
    if any(state is ConditionState.REFUTED for state in relevant):
        return [Outcome.NON_COMPLIANT], Outcome.NON_COMPLIANT, WorkflowStatus.EVALUATED
    if all(state is ConditionState.SUPPORTED for state in relevant):
        return [Outcome.COMPLIANT], Outcome.COMPLIANT, WorkflowStatus.EVALUATED
    return _pending_condition(result, object_id, EXTENDED_KEY_USAGE)


def _pending_binding(
    result: EvaluatedConditions, object_id: str
) -> tuple[list[Outcome], Outcome | None, WorkflowStatus]:
    """绑定未知：证书是否被该对象使用尚未确认，只给可能结论。

    与演示规则一致：绑定未知时可能是「符合」也可能是「部分符合」。
    """
    if not result.gap_ids:
        raise DecisionEngineError(
            f"对象 {object_id} 绑定未知，但快照没有对应缺口，"
            "无法构造符合 Decision 契约的待补证结果"
        )
    return (
        [Outcome.COMPLIANT, Outcome.PARTIALLY_COMPLIANT],
        None,
        WorkflowStatus.PENDING_EVIDENCE,
    )


def _pending_condition(
    result: EvaluatedConditions, object_id: str, condition: str
) -> tuple[list[Outcome], Outcome | None, WorkflowStatus]:
    """前提已确认、但该条件缺证据：该条件的两种取值都还可能。"""
    if not result.gap_ids:
        raise DecisionEngineError(
            f"对象 {object_id} 的条件 {condition} 无法确定，且快照没有可引用缺口；"
            "不能凭空给出唯一结论"
        )
    return (
        [Outcome.COMPLIANT, Outcome.PARTIALLY_COMPLIANT],
        None,
        WorkflowStatus.PENDING_EVIDENCE,
    )


#: 判定规则注册表。``DEMO-BIND-TIME`` 与 ``DEC-BIND-TIME`` 是同一实现的旧、新
#: 两个标识：旧标识保留是为了让既有契约样例与测试继续可用，新标识与规则包清单对齐。
RULE_REGISTRY: dict[str, RuleDefinition] = {
    RULE_ID: RuleDefinition(
        rule_id=RULE_ID,
        evaluate_conditions=_conditions_from_demo,
        map_outcome=_map_bind_time,
        conditions=(BINDING, CERTIFICATE_TIME),
    ),
    RULE_ID_BIND_TIME: RuleDefinition(
        rule_id=RULE_ID_BIND_TIME,
        evaluate_conditions=_conditions_from_demo,
        map_outcome=_map_bind_time,
        conditions=(BINDING, CERTIFICATE_TIME),
    ),
    RULE_KEY_STRENGTH: RuleDefinition(
        rule_id=RULE_KEY_STRENGTH,
        evaluate_conditions=evaluate_certificate_key_strength,
        map_outcome=_map_key_strength,
        conditions=(BINDING, KEY_STRENGTH),
    ),
    RULE_KEY_USAGE: RuleDefinition(
        rule_id=RULE_KEY_USAGE,
        evaluate_conditions=evaluate_certificate_purpose,
        map_outcome=_map_key_usage,
        conditions=(BINDING, KEY_USAGE, EXTENDED_KEY_USAGE),
    ),
}

#: 引擎支持的规则 ID 全集。
SUPPORTED_RULE_IDS = frozenset(RULE_REGISTRY)


def default_rule_ids() -> tuple[str, ...]:
    """新流程默认使用的判定规则，直接取规则包声明为符合性判定的那一层。

    刻意不复制一份列表：规则包改了清单，流程与判定引擎同时跟上，不会出现
    「规则包声明了但流程没跑」的静默漂移。
    """
    return default_rule_set().rule_ids(layer="DECISION")


class DecisionEngine:
    """按规则包声明的规则集合，为快照中的每个对象产出 ``Decision``。

    ``Decision.id`` 由注入的 :class:`IdAllocator` 生成；调用方（成员三）提供
    确定性分配器即可在测试中稳定复现。
    """

    RULE_ID = RULE_ID
    DECISION_ID_PREFIX = DECISION_ID_PREFIX
    RULE_REGISTRY = RULE_REGISTRY
    SUPPORTED_RULE_IDS = SUPPORTED_RULE_IDS

    def __init__(self, id_allocator: IdAllocator):
        self._id_allocator = id_allocator

    def evaluate(
        self, snapshot: EvidenceSnapshot, rule_pack: RulePack
    ) -> list[Decision]:
        _check_rule_pack(snapshot, rule_pack)
        objects = _discover_objects(snapshot)
        decisions: list[Decision] = []
        # 外层按对象、内层按规则：同一对象的判定连续输出，便于报告按对象分组。
        for object_id in objects:
            for rule_id in rule_pack.rule_ids:
                decisions.append(
                    self._evaluate_object(snapshot, rule_pack, object_id, rule_id)
                )
        return decisions

    def _evaluate_object(
        self,
        snapshot: EvidenceSnapshot,
        rule_pack: RulePack,
        object_id: str,
        rule_id: str,
    ) -> Decision:
        definition = RULE_REGISTRY[rule_id]
        result = definition.evaluate_conditions(snapshot, object_id)
        possible_labels, proposed_label, workflow_status = definition.map_outcome(
            result, object_id
        )
        decision_id = self._id_allocator.allocate(
            prefix=self.DECISION_ID_PREFIX, project_id=snapshot.project_id
        )
        return Decision(
            schema_version=snapshot.schema_version,
            id=decision_id,
            snapshot_id=snapshot.id,
            rule_id=rule_id,
            rule_version=rule_pack.version,
            object_id=object_id,
            condition_states=result.states,
            possible_labels=possible_labels,
            proposed_label=proposed_label,
            workflow_status=workflow_status,
            support_fact_ids=result.support_fact_ids,
            gap_ids=result.gap_ids,
        )


def _check_rule_pack(snapshot: EvidenceSnapshot, rule_pack: RulePack) -> None:
    accepted = default_rule_set().accepted_versions
    if snapshot.rule_version not in accepted:
        raise RulePackError(
            f"快照的规则版本 {snapshot.rule_version} 不在规则包接受的版本集合 "
            f"{sorted(accepted)} 内"
        )
    if rule_pack.version != snapshot.rule_version:
        raise RulePackError(
            f"规则包版本 {rule_pack.version} 与快照规则版本 {snapshot.rule_version} 不一致"
        )
    if not rule_pack.rule_ids:
        raise RulePackError("规则包没有列出任何规则")
    rule_ids = set(rule_pack.rule_ids)
    unsupported = rule_ids - SUPPORTED_RULE_IDS
    if unsupported:
        raise RulePackError(f"规则包包含不支持的规则：{sorted(unsupported)}")
    # rule_pack.sm3 由核验端比对规则文件内容；引擎本身不读规则文件。


def _discover_objects(snapshot: EvidenceSnapshot) -> list[str]:
    seen: dict[str, None] = {}
    for fact in snapshot.admitted_facts:
        if fact.scope.asset_id is not None:
            seen.setdefault(fact.scope.asset_id, None)
    for gap in snapshot.gaps:
        if gap.scope.asset_id is not None:
            seen.setdefault(gap.scope.asset_id, None)
    return list(seen)


def _map_outcome(
    states: dict[str, ConditionState],
    gap_ids: list[str],
    object_id: str,
) -> tuple[list[Outcome], Outcome | None, WorkflowStatus]:
    binding = states[BINDING]
    certificate_time = states[CERTIFICATE_TIME]

    if binding is ConditionState.SUPPORTED and certificate_time is ConditionState.SUPPORTED:
        return [Outcome.COMPLIANT], Outcome.COMPLIANT, WorkflowStatus.EVALUATED

    if binding is ConditionState.SUPPORTED and certificate_time is ConditionState.REFUTED:
        # 证书已到期：明确的否定结论。标签映射（NON_COMPLIANT）是临时解释，
        # 0.2.0 协作规范未明示该情形，需团队确认。
        return [Outcome.NON_COMPLIANT], Outcome.NON_COMPLIANT, WorkflowStatus.EVALUATED

    if binding is ConditionState.UNKNOWN:
        if not gap_ids:
            raise DecisionEngineError(
                f"对象 {object_id} 绑定未知，但快照没有对应缺口，"
                "无法构造符合 Decision 契约的待补证结果"
            )
        return (
            [Outcome.COMPLIANT, Outcome.PARTIALLY_COMPLIANT],
            None,
            WorkflowStatus.PENDING_EVIDENCE,
        )

    # 绑定已确认但证书到期时间未知。有对应时间缺口时给出待补证判定：对象确实
    # 使用证书，唯一未定的是证书是否仍有效，因此只保留 COMPLIANT 与
    # NON_COMPLIANT 两种可能，不给唯一建议。
    if not gap_ids:
        raise DecisionEngineError(
            f"对象 {object_id} 绑定已确认但证书到期时间未知，且快照没有可引用缺口，"
            "无法给出唯一结论"
        )
    return [Outcome.COMPLIANT, Outcome.NON_COMPLIANT], None, WorkflowStatus.PENDING_EVIDENCE
