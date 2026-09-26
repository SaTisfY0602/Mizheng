"""Fixed ``DEMO-BIND-TIME`` rule — condition judging only.

Member two owns the decision side. This module provides the small pure
function :func:`evaluate_demo_bind_time` that the forthcoming ``DecisionEngine``
will call to score the two conditions of the demo rule:

* ``binding`` — the target object is confirmed to use a certificate;
* ``certificate_time`` — that bound certificate is still within its validity.

It deliberately does not assemble :class:`Decision` objects, outcome labels,
evidence bundles, reports, or any generic rule language.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from mvp_contracts.models import (
    AdmittedFact,
    ArtifactKind,
    ConditionState,
    EvidenceSnapshot,
    ReviewAction,
)

BINDING = "binding"
CERTIFICATE_TIME = "certificate_time"

_PREDICATE_BINDING = "service_uses_certificate"
_PREDICATE_TIME = "certificate_not_after"
_PREDICATE_CONFIG_PATH = "configured_certificate_path"


class RuleEvaluationError(Exception):
    """固定规则条件求值无法给出结论时抛出。"""


class ConflictingBindingError(RuleEvaluationError):
    """同一对象存在多个指向不同证书的有效绑定，无法唯一选定证书。"""


class UnparseableTimeError(RuleEvaluationError):
    """证书到期时间无法解析，或不是带 UTC 时区的时刻。"""


class AmbiguousScopeError(RuleEvaluationError):
    """对象证据跨越多个环境/链路，共享 Decision 无法按环境独立表达。"""


def evaluate_demo_bind_time(
    snapshot: EvidenceSnapshot,
    object_id: str,
) -> tuple[dict[str, ConditionState], list[str], list[str]]:
    """返回 ``(条件状态, 支持事实 ID, 缺口 ID)``。

    只使用 ``snapshot.admitted_facts`` 支撑条件；``snapshot.candidates`` 仅供
    追溯，不直接证明条件成立。仅考虑 ``scope.asset_id == object_id`` 且适用
    时间覆盖 ``snapshot.evaluation_time`` 的准入事实。
    """
    applicable = [
        fact
        for fact in snapshot.admitted_facts
        if fact.scope.asset_id == object_id
        and _applicable_at(fact.scope, snapshot.evaluation_time)
    ]

    anchor_key = _object_scope_key(snapshot, object_id, applicable)

    binding_facts = _valid_binding_facts(snapshot, applicable, object_id)

    if not binding_facts:
        binding_state = ConditionState.UNKNOWN
        bound_cert_id: str | None = None
        time_fact: AdmittedFact | None = None
    else:
        cert_ids = {fact.value for fact in binding_facts if isinstance(fact.value, str)}
        if len(cert_ids) > 1:
            raise ConflictingBindingError(
                f"对象 {object_id} 存在多个互相矛盾的有效绑定，"
                f"指向不同证书：{sorted(cert_ids)}"
            )
        binding_state = ConditionState.SUPPORTED
        bound_cert_id = next(iter(cert_ids))
        time_fact = _find_time_fact(applicable, binding_facts[0], bound_cert_id)

    # 仅在绑定成立后判断证书时间；绑定未知时，即使快照里另有未绑定证书的
    # 到期时间，证书时间也必须是 UNKNOWN。
    if time_fact is None:
        time_state = ConditionState.UNKNOWN
    else:
        not_after = _parse_not_after(time_fact)
        time_state = (
            ConditionState.SUPPORTED
            if not_after > snapshot.evaluation_time
            else ConditionState.REFUTED
        )

    support_fact_ids = _collect_support_fact_ids(
        snapshot, applicable, binding_facts, time_fact
    )
    gap_ids = _collect_gap_ids(snapshot, object_id, binding_state, anchor_key)

    return {BINDING: binding_state, CERTIFICATE_TIME: time_state}, support_fact_ids, gap_ids


def _applicable_at(scope, evaluation_time: datetime) -> bool:
    if scope.valid_from is not None and evaluation_time < scope.valid_from:
        return False
    if scope.valid_to is not None and evaluation_time > scope.valid_to:
        return False
    return True


def _valid_binding_facts(
    snapshot: EvidenceSnapshot,
    applicable: list[AdmittedFact],
    object_id: str,
) -> list[AdmittedFact]:
    artifacts = {a.id: a for a in snapshot.artifacts}
    reviews = {e.id: e for e in snapshot.review_events}
    result: list[AdmittedFact] = []
    for fact in applicable:
        if fact.predicate != _PREDICATE_BINDING:
            continue
        if not isinstance(fact.value, str):
            continue
        certificate = artifacts.get(fact.value)
        if certificate is None or certificate.kind is not ArtifactKind.CERTIFICATE:
            continue
        if fact.review_event_id is None:
            continue
        review = reviews.get(fact.review_event_id)
        if review is None or review.action is not ReviewAction.CONFIRM_BINDING:
            continue
        if (
            review.target_candidate_id != fact.candidate_id
            or review.confirmed_asset_id != object_id
        ):
            continue
        result.append(fact)
    return result


def _find_time_fact(
    applicable: list[AdmittedFact],
    binding_fact: AdmittedFact,
    bound_cert_id: str,
) -> AdmittedFact | None:
    for fact in applicable:
        if fact.predicate != _PREDICATE_TIME:
            continue
        if fact.artifact_id != bound_cert_id:
            continue
        if not _scope_matches(fact, binding_fact):
            continue
        return fact
    return None


def _scope_matches(fact: AdmittedFact, binding_fact: AdmittedFact) -> bool:
    return (
        fact.scope.project_id == binding_fact.scope.project_id
        and fact.scope.environment == binding_fact.scope.environment
        and fact.scope.asset_id == binding_fact.scope.asset_id
        and fact.scope.link_id == binding_fact.scope.link_id
    )


def _parse_not_after(fact: AdmittedFact) -> datetime:
    value = fact.value
    if not isinstance(value, str):
        raise UnparseableTimeError(
            f"证书到期时间事实 {fact.id} 的值不是时间文本：{value!r}"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise UnparseableTimeError(f"证书到期时间无法解析：{value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise UnparseableTimeError(f"证书到期时间必须带 UTC 时区：{value!r}")
    return parsed


def _collect_support_fact_ids(
    snapshot: EvidenceSnapshot,
    applicable: list[AdmittedFact],
    binding_facts: list[AdmittedFact],
    time_fact: AdmittedFact | None,
) -> list[str]:
    referenced: set[str] = {fact.id for fact in binding_facts}
    if time_fact is not None:
        referenced.add(time_fact.id)
    # A configured certificate path is cited as context ("发现了配置路径"), but
    # it never upgrades ``binding`` to SUPPORTED by itself.
    for fact in applicable:
        if fact.predicate == _PREDICATE_CONFIG_PATH:
            referenced.add(fact.id)
    return [fact.id for fact in snapshot.admitted_facts if fact.id in referenced]


def _scope_key(scope) -> tuple[str, str, str | None]:
    """环境的判别键：缺口必须与对象证据落在同一 project/环境/链路。"""
    return (scope.project_id, scope.environment, scope.link_id)


def _object_scope_key(
    snapshot: EvidenceSnapshot,
    object_id: str,
    applicable: list[AdmittedFact],
) -> tuple[str, str, str | None] | None:
    """确定对象唯一的环境范围；跨越多个环境/链路时显式失败。

    共享 ``Decision`` 只有 ``object_id``，无法按环境独立表达同一对象的多个判定。
    因此把核查时间适用的准入事实与缺口的范围（project/environment/link）一起收集，
    出现多个范围即抛 :class:`AmbiguousScopeError`，不猜选范围。不适用核查时间的
    历史缺口不参与范围判定，不会造成歧义。
    """
    keys = {_scope_key(f.scope) for f in applicable}
    keys.update(
        _scope_key(g.scope)
        for g in snapshot.gaps
        if g.scope.asset_id == object_id
        and _applicable_at(g.scope, snapshot.evaluation_time)
    )
    if len(keys) > 1:
        raise AmbiguousScopeError(
            f"对象 {object_id} 的证据跨越多个环境/链路，"
            "共享 Decision 无法按环境独立表达；请拆分对象或明确单一范围"
        )
    return next(iter(keys)) if keys else None


def _collect_gap_ids(
    snapshot: EvidenceSnapshot,
    object_id: str,
    binding_state: ConditionState,
    anchor_key: tuple[str, str, str | None] | None,
) -> list[str]:
    """收集对象适用范围内的既有缺口，保持快照中的原始顺序。

    缺口必须落在对象的唯一环境范围（``anchor_key``）内；其它环境/链路的缺口
    不能冒充本对象当前绑定证书的缺口。并按绑定状态区分缺口类型：绑定未知时只
    引用 ``binding`` 缺口；绑定已确认时只引用 ``certificate_time`` 缺口——陈旧
    的 ``binding`` 缺口不能顶替证书时间缺口。核验器不自行制造缺口。
    """
    result: list[str] = []
    for gap in snapshot.gaps:
        if gap.scope.asset_id != object_id:
            continue
        if not _applicable_at(gap.scope, snapshot.evaluation_time):
            continue
        if _scope_key(gap.scope) != anchor_key:
            continue
        if binding_state is ConditionState.UNKNOWN and gap.target_condition == BINDING:
            result.append(gap.id)
        elif (
            binding_state is ConditionState.SUPPORTED
            and gap.target_condition == CERTIFICATE_TIME
        ):
            result.append(gap.id)
    return result
