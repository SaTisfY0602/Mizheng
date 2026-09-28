"""判定侧规则的语义测试：多规则注册表、密钥强度、证书用途。

这些测试跑**真实模式**拿到一份定稿快照，再定点改写事实值来构造边界情形——
弱密钥与缺字段的证书用真实材料造不出来（``cryptography`` 会直接拒绝），
所以只能对已准入事实做定点改写，这一点与风险侧测试的做法一致。

断言刻意读取快照里的真实 ID，而不是硬编码，这样规则返回罐头值时会失败。
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.models import (
    ConditionState,
    Decision,
    EvidenceSnapshot,
    Gap,
    Outcome,
    RulePack,
    WorkflowStatus,
)
from mvp_decision import DecisionEngine, RulePackError
from mvp_flow import IdAllocator, run_case
from mvp_flow.pipeline import MODE_REAL
from mvp_rules import default_rule_set, rule_pack_sm3

FIXED_NOW = datetime(2026, 9, 28, 0, 0, 0, tzinfo=timezone.utc)

BINDING = "binding"
CERTIFICATE_TIME = "certificate_time"
KEY_STRENGTH = "key_strength"
KEY_USAGE = "key_usage"
EXTENDED_KEY_USAGE = "extended_key_usage"

RULE_BIND_TIME = "DEC-BIND-TIME"
RULE_KEY_STRENGTH = "DEC-CERT-KEY-STRENGTH"
RULE_KEY_USAGE = "DEC-CERT-KEY-USAGE"
CERTIFICATE_EVIDENCE = "certificate_evidence"

_SNAPSHOT: EvidenceSnapshot | None = None


def _complete_snapshot() -> EvidenceSnapshot:
    """跑一次真实模式的 complete 样例，把定稿快照缓存下来给全部用例复用。"""
    global _SNAPSHOT
    if _SNAPSHOT is None:
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )
            path = Path(record.bundle_path) / "snapshot" / f"{record.snapshot_id}.json"
            _SNAPSHOT = EvidenceSnapshot.model_validate_json(
                path.read_text(encoding="utf-8")
            )
    return _SNAPSHOT


def _rule_pack(snapshot: EvidenceSnapshot, rule_ids=()) -> RulePack:
    return RulePack(
        id="RP-CRYPTO-ASSESS",
        version=snapshot.rule_version,
        sm3=rule_pack_sm3(),
        rule_ids=list(rule_ids) or list(default_rule_set().rules_for_version(snapshot.rule_version)),
    )


def _evaluate(snapshot: EvidenceSnapshot) -> list[Decision]:
    return DecisionEngine(IdAllocator()).evaluate(snapshot, _rule_pack(snapshot))


def _decision(decisions: list[Decision], rule_id: str) -> Decision:
    matched = [d for d in decisions if d.rule_id == rule_id]
    if len(matched) != 1:
        raise AssertionError(f"期望恰好一条 {rule_id} 判定，实际 {len(matched)} 条")
    return matched[0]


def _binding_fact(snapshot: EvidenceSnapshot):
    return next(
        f for f in snapshot.admitted_facts if f.predicate == "service_uses_certificate"
    )


def _patch_facts(
    snapshot: EvidenceSnapshot, predicate: str, value: object
) -> EvidenceSnapshot:
    return snapshot.model_copy(
        update={
            "admitted_facts": [
                f.model_copy(update={"value": value}) if f.predicate == predicate else f
                for f in snapshot.admitted_facts
            ]
        }
    )


def _drop_facts(snapshot: EvidenceSnapshot, predicate: str) -> EvidenceSnapshot:
    return snapshot.model_copy(
        update={
            "admitted_facts": [
                f for f in snapshot.admitted_facts if f.predicate != predicate
            ]
        }
    )


def _with_extra_fact(
    snapshot: EvidenceSnapshot, predicate: str, value: object
) -> EvidenceSnapshot:
    """新增一条准入事实（连同它的候选），用于覆盖解析器造不出来的情形。

    契约要求准入事实逐字段等于它引用的候选，所以只加事实不加候选是无效快照。
    """
    source_fact = next(
        f for f in snapshot.admitted_facts if f.predicate == "certificate_not_after"
    )
    source_candidate = next(
        c for c in snapshot.candidates if c.id == source_fact.candidate_id
    )
    new_candidate = source_candidate.model_copy(
        update={"id": f"CAND-TEST-{predicate}", "predicate": predicate, "value": value}
    )
    new_fact = source_fact.model_copy(
        update={
            "id": f"FACT-TEST-{predicate}",
            "candidate_id": new_candidate.id,
            "predicate": predicate,
            "value": value,
        }
    )
    return snapshot.model_copy(
        update={
            "candidates": [*snapshot.candidates, new_candidate],
            "admitted_facts": [*snapshot.admitted_facts, new_fact],
        }
    )


def _with_gap(
    snapshot: EvidenceSnapshot, *, target_condition: str, reason_code: str
) -> EvidenceSnapshot:
    """给快照补一条缺口，落在被评价对象所在的范围上。

    刻意不依赖绑定事实：绑定缺失的用例里已经没有绑定事实了，仍要能补缺口。
    """
    scope = next(
        fact.scope for fact in snapshot.admitted_facts if fact.scope.asset_id is not None
    )
    gap = Gap(
        id="GAP-TEST-001",
        target_condition=target_condition,
        reason_code=reason_code,
        scope=scope,
        description="测试用缺口",
    )
    return snapshot.model_copy(update={"gaps": [*snapshot.gaps, gap]})


class RuleRegistryTest(unittest.TestCase):
    """引擎按规则包声明跑规则；规则集合完全由 ``rule_ids`` 决定。"""

    def test_real_materials_run_three_rules_per_object(self):
        snapshot = _complete_snapshot()

        decisions = _evaluate(snapshot)

        objects = {f.scope.asset_id for f in snapshot.admitted_facts if f.scope.asset_id}
        expected_rules = set(default_rule_set().rules_for_version(snapshot.rule_version))
        self.assertEqual(len(decisions), len(objects) * len(expected_rules))
        self.assertEqual(
            {d.rule_id for d in decisions},
            expected_rules,
        )

    def test_decision_ids_are_unique(self):
        decisions = _evaluate(_complete_snapshot())

        ids = [d.id for d in decisions]
        self.assertEqual(len(ids), len(set(ids)))

    def test_legacy_rule_id_still_supported(self):
        """历史契约样例用的是 DEMO-BIND-TIME，必须继续可用。"""
        snapshot = _complete_snapshot()
        pack = _rule_pack(snapshot, rule_ids=["DEMO-BIND-TIME"])

        decisions = DecisionEngine(IdAllocator()).evaluate(snapshot, pack)

        self.assertEqual({d.rule_id for d in decisions}, {"DEMO-BIND-TIME"})

    def test_pack_with_unknown_rule_is_rejected(self):
        snapshot = _complete_snapshot()

        with self.assertRaises(RulePackError):
            DecisionEngine(IdAllocator()).evaluate(
                snapshot, _rule_pack(snapshot, rule_ids=["NOT-A-RULE"])
            )

    def test_pack_with_no_rules_is_rejected(self):
        snapshot = _complete_snapshot()
        pack = RulePack(
            id="RP-CRYPTO-ASSESS",
            version=snapshot.rule_version,
            sm3=rule_pack_sm3(),
            rule_ids=[],
        )

        with self.assertRaises(RulePackError):
            DecisionEngine(IdAllocator()).evaluate(snapshot, pack)

    def test_snapshot_with_unaccepted_rule_version_is_rejected(self):
        snapshot = _complete_snapshot().model_copy(
            update={"rule_version": "2099.0"}
        )

        with self.assertRaises(RulePackError):
            DecisionEngine(IdAllocator()).evaluate(snapshot, _rule_pack(snapshot))


class KeyStrengthRuleTest(unittest.TestCase):
    """``DEC-CERT-KEY-STRENGTH``：RSA 下限来自规则包，缺证据停在待补证。"""

    def test_strong_key_is_compliant(self):
        decision = _decision(_evaluate(_complete_snapshot()), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[BINDING], ConditionState.SUPPORTED)
        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.SUPPORTED)
        self.assertEqual(decision.proposed_label, Outcome.COMPLIANT)
        self.assertEqual(decision.workflow_status, WorkflowStatus.EVALUATED)

    def test_short_rsa_key_is_non_compliant(self):
        snapshot = _patch_facts(_complete_snapshot(), "certificate_public_key_size", 1024)

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.REFUTED)
        self.assertEqual(decision.proposed_label, Outcome.NON_COMPLIANT)
        self.assertEqual(decision.possible_labels, [Outcome.NON_COMPLIANT])

    def test_threshold_comes_from_rule_pack(self):
        """恰好等于规则包下限的密钥必须通过。"""
        minimum = default_rule_set().int_param(RULE_KEY_STRENGTH, "min_rsa_key_size")
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_public_key_size", minimum
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.SUPPORTED)

    def test_one_bit_below_threshold_is_refuted(self):
        minimum = default_rule_set().int_param(RULE_KEY_STRENGTH, "min_rsa_key_size")
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_public_key_size", minimum - 1
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.REFUTED)

    def test_missing_key_facts_pend_with_evidence_gap(self):
        """缺公钥事实不能算通过；有对应缺口时停在待补证。"""
        snapshot = _drop_facts(_complete_snapshot(), "certificate_public_key_size")
        snapshot = _with_gap(
            snapshot,
            target_condition=CERTIFICATE_EVIDENCE,
            reason_code="MISSING_CERTIFICATE_EVIDENCE",
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.UNKNOWN)
        self.assertIsNone(decision.proposed_label)
        self.assertEqual(decision.workflow_status, WorkflowStatus.PENDING_EVIDENCE)
        self.assertTrue(decision.gap_ids)

    def test_missing_key_facts_without_gap_fail_loudly(self):
        """没有缺口就既不能判通过、也不能凭空给待补证——必须显式失败。"""
        snapshot = _drop_facts(_complete_snapshot(), "certificate_public_key_size")

        with self.assertRaises(Exception) as caught:
            _evaluate(snapshot)

        self.assertIn("key_strength", str(caught.exception))

    def test_non_rsa_without_curve_pends(self):
        """非 RSA 且没有曲线事实时无法判断强度，同样停在待补证。"""
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_public_key_algorithm", "EllipticCurvePublicKey"
        )
        snapshot = _with_gap(
            snapshot,
            target_condition=CERTIFICATE_EVIDENCE,
            reason_code="MISSING_CERTIFICATE_EVIDENCE",
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.UNKNOWN)

    def test_non_rsa_weak_curve_is_refuted(self):
        weak_curve = default_rule_set().str_tuple_param(RULE_KEY_STRENGTH, "weak_curves")[0]
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_public_key_algorithm", "EllipticCurvePublicKey"
        )
        snapshot = _with_extra_fact(
            snapshot, "certificate_public_key_curve", weak_curve
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.REFUTED)

    def test_non_rsa_strong_curve_is_supported(self):
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_public_key_algorithm", "EllipticCurvePublicKey"
        )
        snapshot = _with_extra_fact(
            snapshot, "certificate_public_key_curve", "secp256r1"
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_STRENGTH)

        self.assertEqual(decision.condition_states[KEY_STRENGTH], ConditionState.SUPPORTED)


class CertificatePurposeRuleTest(unittest.TestCase):
    """``DEC-CERT-KEY-USAGE``：缺用途证据只能停在待补证，不得当成否定。"""

    def test_server_auth_certificate_is_compliant(self):
        decision = _decision(_evaluate(_complete_snapshot()), RULE_KEY_USAGE)

        self.assertEqual(decision.condition_states[EXTENDED_KEY_USAGE], ConditionState.SUPPORTED)
        self.assertEqual(decision.condition_states[KEY_USAGE], ConditionState.SUPPORTED)
        self.assertEqual(decision.proposed_label, Outcome.COMPLIANT)

    def test_eku_without_server_auth_is_non_compliant(self):
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_extended_key_usage", ["clientAuth"]
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_USAGE)

        self.assertEqual(decision.condition_states[EXTENDED_KEY_USAGE], ConditionState.REFUTED)
        self.assertEqual(decision.proposed_label, Outcome.NON_COMPLIANT)

    def test_key_usage_without_required_bits_is_non_compliant(self):
        snapshot = _patch_facts(
            _complete_snapshot(), "certificate_key_usage", ["key_agreement"]
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_USAGE)

        self.assertEqual(decision.condition_states[KEY_USAGE], ConditionState.REFUTED)

    def test_missing_usage_extensions_pend_with_evidence_gap(self):
        """证书确实没有用途扩展时，解析器不产出该字段事实；判定必须停在待补证。"""
        snapshot = _drop_facts(_complete_snapshot(), "certificate_key_usage")
        snapshot = _drop_facts(snapshot, "certificate_extended_key_usage")
        snapshot = _with_gap(
            snapshot,
            target_condition=CERTIFICATE_EVIDENCE,
            reason_code="MISSING_CERTIFICATE_EVIDENCE",
        )

        decision = _decision(_evaluate(snapshot), RULE_KEY_USAGE)

        self.assertEqual(decision.condition_states[KEY_USAGE], ConditionState.UNKNOWN)
        self.assertEqual(
            decision.condition_states[EXTENDED_KEY_USAGE], ConditionState.UNKNOWN
        )
        self.assertIsNone(decision.proposed_label)
        self.assertEqual(decision.workflow_status, WorkflowStatus.PENDING_EVIDENCE)
        # 待补证必须能指出自己缺什么
        self.assertTrue(decision.gap_ids)

    def test_purpose_gap_is_not_hijacked_by_binding_gap(self):
        """绑定已确认时，旧绑定缺口不能顶替用途缺口。"""
        snapshot = _drop_facts(_complete_snapshot(), "certificate_key_usage")
        snapshot = _drop_facts(snapshot, "certificate_extended_key_usage")
        snapshot = _with_gap(
            snapshot, target_condition="binding", reason_code="MISSING_BINDING"
        )

        # 只有绑定缺口、没有用途缺口：不应被当成用途待补证的依据
        with self.assertRaises(Exception):
            _evaluate(snapshot)


class BindingPreconditionTest(unittest.TestCase):
    """绑定未确认是**所有**判定规则的共同前提。"""

    def test_all_rules_stop_at_unknown_binding(self):
        snapshot = _drop_facts(_complete_snapshot(), "service_uses_certificate")
        snapshot = _with_gap(
            snapshot, target_condition=BINDING, reason_code="MISSING_BINDING"
        )

        decisions = _evaluate(snapshot)

        self.assertTrue(decisions)
        for decision in decisions:
            with self.subTest(rule_id=decision.rule_id):
                self.assertEqual(
                    decision.condition_states[BINDING], ConditionState.UNKNOWN
                )
                self.assertIsNone(decision.proposed_label)
                self.assertEqual(
                    decision.workflow_status, WorkflowStatus.PENDING_EVIDENCE
                )
                # 只引用绑定缺口，不引用其它条件的缺口
                self.assertEqual(decision.gap_ids, ["GAP-TEST-001"])


class RuleSetVersionTest(unittest.TestCase):
    """每个快照规则版本跑它声明的那组规则，不因缺字段产出假阴性。"""

    def test_historical_version_runs_only_its_declared_subset(self):
        snapshot = _complete_snapshot().model_copy(update={"rule_version": "demo-0.2.0"})
        # demo-0.2.0 只声明 DEC-BIND-TIME，所以包里的规则也要跟着变
        pack = RulePack(
            id="RP-CRYPTO-ASSESS",
            version="demo-0.2.0",
            sm3=rule_pack_sm3(),
            rule_ids=list(default_rule_set().rules_for_version("demo-0.2.0")),
        )

        decisions = DecisionEngine(IdAllocator()).evaluate(snapshot, pack)

        self.assertEqual({d.rule_id for d in decisions}, {RULE_BIND_TIME})
        # 该版本下不该出现密钥强度/用途判定
        self.assertNotIn(RULE_KEY_STRENGTH, {d.rule_id for d in decisions})

    def test_current_version_declares_all_three_rules(self):
        rule_set = default_rule_set()

        self.assertEqual(
            set(rule_set.rules_for_version(rule_set.meta.version)),
            {RULE_BIND_TIME, RULE_KEY_STRENGTH, RULE_KEY_USAGE},
        )


if __name__ == "__main__":
    unittest.main()
