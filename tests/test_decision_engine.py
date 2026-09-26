"""Tests for the DEMO-BIND-TIME DecisionEngine assembly.

These tests exercise :class:`mvp_decision.DecisionEngine` against the two
hand-off snapshots and derived variants. Assertions are semantic: expected
object ids, fact ids and gap ids are read from the snapshot rather than
hardcoded, and the decision id is produced by a deterministic injected
allocator instead of the sample's own ``DEC-*`` ids.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from mvp_contracts.models import (
    ConditionState,
    Decision,
    EvidenceSnapshot,
    Gap,
    Outcome,
    ReviewAction,
    RulePack,
    WorkflowStatus,
)
from mvp_decision import DecisionEngine
from mvp_decision.engine import DecisionEngineError, RulePackError
from mvp_decision.rules import AmbiguousScopeError, ConflictingBindingError, UnparseableTimeError


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "contracts" / "0.2.0-mvp"


class _RecordingIdAllocator:
    """Deterministic stand-in for the injected IdAllocator."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self._count = 0

    def allocate(self, *, prefix: str, project_id: str) -> str:
        self._count += 1
        self.calls.append((prefix, project_id))
        return f"{prefix}-{project_id}-{self._count:03d}"


def _load_snapshot(name: str) -> EvidenceSnapshot:
    payload = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
    return EvidenceSnapshot.model_validate(payload["snapshots"][-1])


def _rule_pack(snapshot: EvidenceSnapshot, *, version=None, rule_ids=None) -> RulePack:
    return RulePack(
        id="RP-DEMO-BIND-TIME",
        version=snapshot.rule_version if version is None else version,
        sm3="0" * 64,
        rule_ids=["DEMO-BIND-TIME"] if rule_ids is None else rule_ids,
    )


def _binding_fact(snapshot: EvidenceSnapshot):
    return next(f for f in snapshot.admitted_facts if f.predicate == "service_uses_certificate")


def _bound_time_fact(snapshot: EvidenceSnapshot, binding_fact):
    return next(
        f
        for f in snapshot.admitted_facts
        if f.predicate == "certificate_not_after" and f.artifact_id == binding_fact.value
    )


def _make_conflicting(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
    """Add a second, differently-certified confirmed binding to the same object."""
    bind_fact = _binding_fact(snapshot)
    original_cert = next(a for a in snapshot.artifacts if a.id == bind_fact.value)
    cert2 = original_cert.model_copy(update={"id": "EVD-CERT-003"})

    bind_candidate = next(
        c for c in snapshot.candidates if c.predicate == "service_uses_certificate"
    )
    candidate2 = bind_candidate.model_copy(
        update={"id": "CAND-BIND-003", "value": cert2.id}
    )
    fact2 = bind_fact.model_copy(
        update={
            "id": "FACT-BIND-003",
            "candidate_id": candidate2.id,
            "value": cert2.id,
            "review_event_id": "REV-BIND-003",
        }
    )
    confirm_event = next(
        e for e in snapshot.review_events if e.action is ReviewAction.CONFIRM_BINDING
    )
    event2 = confirm_event.model_copy(
        update={"id": "REV-BIND-003", "target_candidate_id": candidate2.id}
    )

    return snapshot.model_copy(
        update={
            "artifacts": snapshot.artifacts + [cert2],
            "candidates": snapshot.candidates + [candidate2],
            "admitted_facts": snapshot.admitted_facts + [fact2],
            "review_events": snapshot.review_events + [event2],
        }
    )


def _make_naive_time(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
    naive = "2026-12-31T23:59:59"  # missing the UTC "Z" suffix
    return snapshot.model_copy(
        update={
            "admitted_facts": [
                (
                    f.model_copy(update={"value": naive})
                    if f.predicate == "certificate_not_after"
                    else f
                )
                for f in snapshot.admitted_facts
            ],
            "candidates": [
                (
                    c.model_copy(update={"value": naive})
                    if c.predicate == "certificate_not_after"
                    else c
                )
                for c in snapshot.candidates
            ],
        }
    )


def _strip_time_fact(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
    """Remove the admitted certificate_not_after fact, leaving binding confirmed."""
    return snapshot.model_copy(
        update={
            "admitted_facts": [
                f
                for f in snapshot.admitted_facts
                if f.predicate != "certificate_not_after"
            ]
        }
    )


def _with_certificate_time_gap(
    snapshot: EvidenceSnapshot, *, gap_id: str = "GAP-TIME-001"
) -> EvidenceSnapshot:
    binding_fact = next(
        f for f in snapshot.admitted_facts if f.predicate == "service_uses_certificate"
    )
    gap = Gap(
        schema_version=snapshot.schema_version,
        id=gap_id,
        target_condition="certificate_time",
        reason_code="MISSING_NOT_AFTER",
        scope=binding_fact.scope,
        description="缺少已绑定证书的到期时间",
    )
    return snapshot.model_copy(update={"gaps": snapshot.gaps + [gap]})


def _rename_object(snapshot: EvidenceSnapshot, old_id: str, new_id: str) -> EvidenceSnapshot:
    def rename_scope(scope):
        return scope.model_copy(update={"asset_id": new_id}) if scope.asset_id == old_id else scope

    return snapshot.model_copy(
        update={
            "admitted_facts": [
                f.model_copy(update={"scope": rename_scope(f.scope)})
                for f in snapshot.admitted_facts
            ],
            "candidates": [
                c.model_copy(update={"scope": rename_scope(c.scope)})
                for c in snapshot.candidates
            ],
            "gaps": [
                g.model_copy(update={"scope": rename_scope(g.scope)})
                for g in snapshot.gaps
            ],
            "review_events": [
                (
                    e.model_copy(update={"confirmed_asset_id": new_id})
                    if e.confirmed_asset_id == old_id
                    else e
                )
                for e in snapshot.review_events
            ],
        }
    )


class DecisionEngineTest(unittest.TestCase):
    def test_complete_snapshot_yields_single_compliant_decision(self):
        snapshot = _load_snapshot("complete.json")
        bind_fact = _binding_fact(snapshot)
        time_fact = _bound_time_fact(snapshot, bind_fact)
        allocator = _RecordingIdAllocator()

        decisions = DecisionEngine(allocator).evaluate(snapshot, _rule_pack(snapshot))

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertIsInstance(decision, Decision)
        self.assertEqual(decision.snapshot_id, snapshot.id)
        self.assertEqual(decision.rule_id, DecisionEngine.RULE_ID)
        self.assertEqual(decision.rule_version, snapshot.rule_version)
        self.assertEqual(decision.object_id, bind_fact.scope.asset_id)
        self.assertEqual(
            decision.condition_states,
            {
                "binding": ConditionState.SUPPORTED,
                "certificate_time": ConditionState.SUPPORTED,
            },
        )
        self.assertEqual(decision.possible_labels, [Outcome.COMPLIANT])
        self.assertEqual(decision.proposed_label, Outcome.COMPLIANT)
        self.assertEqual(decision.workflow_status, WorkflowStatus.EVALUATED)
        self.assertEqual(decision.support_fact_ids, [bind_fact.id, time_fact.id])
        self.assertEqual(decision.gap_ids, [])
        # Id allocator was asked for a decision id against the snapshot project.
        self.assertEqual(allocator.calls, [(DecisionEngine.DECISION_ID_PREFIX, snapshot.project_id)])

    def test_missing_binding_yields_pending_evidence(self):
        snapshot = _load_snapshot("missing_binding.json")
        path_fact = next(
            f for f in snapshot.admitted_facts if f.predicate == "configured_certificate_path"
        )
        missing_gap = next(g for g in snapshot.gaps if g.reason_code == "MISSING_BINDING")

        decisions = DecisionEngine(_RecordingIdAllocator()).evaluate(
            snapshot, _rule_pack(snapshot)
        )

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision.object_id, path_fact.scope.asset_id)
        self.assertEqual(
            decision.condition_states,
            {
                "binding": ConditionState.UNKNOWN,
                "certificate_time": ConditionState.UNKNOWN,
            },
        )
        self.assertEqual(decision.possible_labels, [Outcome.COMPLIANT, Outcome.PARTIALLY_COMPLIANT])
        self.assertIsNone(decision.proposed_label)
        self.assertEqual(decision.workflow_status, WorkflowStatus.PENDING_EVIDENCE)
        self.assertEqual(decision.support_fact_ids, [path_fact.id])
        self.assertEqual(decision.gap_ids, [missing_gap.id])

    def test_expired_certificate_maps_to_non_compliant(self):
        snapshot = _load_snapshot("complete.json")
        bind_fact = _binding_fact(snapshot)
        time_fact = _bound_time_fact(snapshot, bind_fact)
        not_after = datetime.fromisoformat(time_fact.value)
        moved = snapshot.model_copy(
            update={"evaluation_time": not_after + timedelta(days=1)}
        )

        decisions = DecisionEngine(_RecordingIdAllocator()).evaluate(
            moved, _rule_pack(moved)
        )

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision.condition_states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(decision.condition_states["certificate_time"], ConditionState.REFUTED)
        self.assertEqual(decision.possible_labels, [Outcome.NON_COMPLIANT])
        self.assertEqual(decision.proposed_label, Outcome.NON_COMPLIANT)
        self.assertEqual(decision.workflow_status, WorkflowStatus.EVALUATED)

    def test_rule_pack_version_mismatch_fails(self):
        snapshot = _load_snapshot("complete.json")
        bad_pack = _rule_pack(snapshot, version="some-other-version")

        with self.assertRaises(RulePackError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(snapshot, bad_pack)

    def test_unsupported_rule_fails(self):
        snapshot = _load_snapshot("complete.json")
        engine = DecisionEngine(_RecordingIdAllocator())

        with self.assertRaises(RulePackError):
            engine.evaluate(snapshot, _rule_pack(snapshot, rule_ids=["DEMO-OTHER-RULE"]))
        with self.assertRaises(RulePackError):
            engine.evaluate(
                snapshot,
                _rule_pack(snapshot, rule_ids=["DEMO-BIND-TIME", "DEMO-OTHER-RULE"]),
            )

    def test_conflicting_bindings_propagate(self):
        snapshot = _make_conflicting(_load_snapshot("complete.json"))

        with self.assertRaises(ConflictingBindingError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(
                snapshot, _rule_pack(snapshot)
            )

    def test_unparseable_time_propagates(self):
        snapshot = _make_naive_time(_load_snapshot("complete.json"))

        with self.assertRaises(UnparseableTimeError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(
                snapshot, _rule_pack(snapshot)
            )

    def test_decision_uses_discovered_object_id_not_hardcoded(self):
        snapshot = _rename_object(_load_snapshot("complete.json"), "APP-01", "ASSET-CUSTOM")
        allocator = _RecordingIdAllocator()

        decisions = DecisionEngine(allocator).evaluate(snapshot, _rule_pack(snapshot))

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision.object_id, "ASSET-CUSTOM")
        self.assertEqual(decision.condition_states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(decision.proposed_label, Outcome.COMPLIANT)
        self.assertEqual(allocator.calls, [(DecisionEngine.DECISION_ID_PREFIX, snapshot.project_id)])

    def test_binding_unknown_without_gap_errors(self):
        # A confirmed binding is removed from the snapshot's admitted facts, but
        # no binding gap exists — so no conforming PENDING_EVIDENCE decision can
        # be built, and the engine must fail rather than fabricate a gap.
        snapshot = _load_snapshot("complete.json")
        admitted = [
            f for f in snapshot.admitted_facts if f.predicate != "service_uses_certificate"
        ]
        stripped = snapshot.model_copy(update={"admitted_facts": admitted})

        with self.assertRaises(DecisionEngineError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(
                stripped, _rule_pack(stripped)
            )

    def test_bound_without_time_but_with_gap_yields_pending_evidence(self):
        snapshot = _with_certificate_time_gap(
            _strip_time_fact(_load_snapshot("complete.json"))
        )
        bind_fact = _binding_fact(snapshot)

        decisions = DecisionEngine(_RecordingIdAllocator()).evaluate(
            snapshot, _rule_pack(snapshot)
        )

        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision.object_id, bind_fact.scope.asset_id)
        self.assertEqual(
            decision.condition_states,
            {"binding": ConditionState.SUPPORTED, "certificate_time": ConditionState.UNKNOWN},
        )
        self.assertEqual(
            decision.possible_labels, [Outcome.COMPLIANT, Outcome.NON_COMPLIANT]
        )
        self.assertIsNone(decision.proposed_label)
        self.assertEqual(decision.workflow_status, WorkflowStatus.PENDING_EVIDENCE)
        self.assertEqual(decision.gap_ids, ["GAP-TIME-001"])

    def test_bound_without_time_and_without_gap_errors(self):
        snapshot = _strip_time_fact(_load_snapshot("complete.json"))

        with self.assertRaises(DecisionEngineError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(
                snapshot, _rule_pack(snapshot)
            )

    def test_bound_without_time_but_only_binding_gap_errors(self):
        snapshot = _strip_time_fact(_load_snapshot("complete.json"))
        bind_fact = _binding_fact(snapshot)
        stale_binding_gap = Gap(
            schema_version=snapshot.schema_version,
            id="GAP-BIND-STALE",
            target_condition="binding",
            reason_code="MISSING_BINDING",
            scope=bind_fact.scope,
            description="陈旧的绑定缺口，不应满足证书时间缺口",
        )
        snapshot = snapshot.model_copy(update={"gaps": snapshot.gaps + [stale_binding_gap]})

        with self.assertRaises(DecisionEngineError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(
                snapshot, _rule_pack(snapshot)
            )

    def test_fact_gap_cross_environment_raises_ambiguity(self):
        snapshot = _load_snapshot("complete.json")
        bind_fact = _binding_fact(snapshot)
        staging_gap = Gap(
            schema_version=snapshot.schema_version,
            id="GAP-BIND-STAGING",
            target_condition="binding",
            reason_code="MISSING_BINDING",
            scope=bind_fact.scope.model_copy(update={"environment": "STAGING"}),
            description="同一对象在 STAGING 的绑定缺口",
        )
        snapshot = snapshot.model_copy(update={"gaps": snapshot.gaps + [staging_gap]})

        with self.assertRaises(AmbiguousScopeError):
            DecisionEngine(_RecordingIdAllocator()).evaluate(
                snapshot, _rule_pack(snapshot)
            )


if __name__ == "__main__":
    unittest.main()
