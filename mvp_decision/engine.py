"""Decision engine assembling shared ``Decision`` objects for the demo rule.

Member two owns the decision side. This engine reuses the condition function
:func:`mvp_decision.rules.evaluate_demo_bind_time` — it does not reimplement
any condition logic — and only turns its results into :class:`Decision` objects.
It implements only ``DEMO-BIND-TIME``; evidence bundles, the verifier, reports
and a generic rule language are out of scope here.
"""

from __future__ import annotations

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import (
    ConditionState,
    Decision,
    EvidenceSnapshot,
    Outcome,
    RulePack,
    WorkflowStatus,
)

from .rules import BINDING, CERTIFICATE_TIME, evaluate_demo_bind_time

RULE_ID = "DEMO-BIND-TIME"
DECISION_ID_PREFIX = "DEC"
SUPPORTED_RULE_IDS = frozenset({RULE_ID})


class DecisionEngineError(Exception):
    """判定引擎无法产出符合契约的判定时抛出。"""


class RulePackError(DecisionEngineError):
    """规则包版本或内容不受支持。"""


class DecisionEngine:
    """把 ``DEMO-BIND-TIME`` 的条件结果组装成 ``Decision`` 列表。

    ``Decision.id`` 由注入的 :class:`IdAllocator` 生成；调用方（成员三）提供
    确定性分配器即可在测试中稳定复现。
    """

    RULE_ID = RULE_ID
    DECISION_ID_PREFIX = DECISION_ID_PREFIX

    def __init__(self, id_allocator: IdAllocator):
        self._id_allocator = id_allocator

    def evaluate(
        self, snapshot: EvidenceSnapshot, rule_pack: RulePack
    ) -> list[Decision]:
        _check_rule_pack(snapshot, rule_pack)
        return [
            self._evaluate_object(snapshot, rule_pack, object_id)
            for object_id in _discover_objects(snapshot)
        ]

    def _evaluate_object(
        self, snapshot: EvidenceSnapshot, rule_pack: RulePack, object_id: str
    ) -> Decision:
        states, support_fact_ids, gap_ids = evaluate_demo_bind_time(snapshot, object_id)
        possible_labels, proposed_label, workflow_status = _map_outcome(
            states, gap_ids, object_id
        )
        decision_id = self._id_allocator.allocate(
            prefix=self.DECISION_ID_PREFIX, project_id=snapshot.project_id
        )
        return Decision(
            schema_version=snapshot.schema_version,
            id=decision_id,
            snapshot_id=snapshot.id,
            rule_id=self.RULE_ID,
            rule_version=rule_pack.version,
            object_id=object_id,
            condition_states=states,
            possible_labels=possible_labels,
            proposed_label=proposed_label,
            workflow_status=workflow_status,
            support_fact_ids=support_fact_ids,
            gap_ids=gap_ids,
        )


def _check_rule_pack(snapshot: EvidenceSnapshot, rule_pack: RulePack) -> None:
    if rule_pack.version != snapshot.rule_version:
        raise RulePackError(
            f"规则包版本 {rule_pack.version} 与快照规则版本 {snapshot.rule_version} 不一致"
        )
    rule_ids = set(rule_pack.rule_ids)
    if RULE_ID not in rule_ids:
        raise RulePackError(f"规则包未包含受支持的规则 {RULE_ID}")
    unsupported = rule_ids - SUPPORTED_RULE_IDS
    if unsupported:
        raise RulePackError(f"规则包包含不支持的规则：{sorted(unsupported)}")
    # rule_pack.sm3 在本阶段仅是契约字段，引擎不声称已核验规则包文件。


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
