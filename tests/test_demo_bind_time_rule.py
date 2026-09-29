"""Semantic tests for the DEMO-BIND-TIME condition-evaluation function.

These tests exercise :func:`mvp_decision.rules.evaluate_demo_bind_time` against
the two hand-off snapshots and a few derived variants. Assertions are semantic:
they derive object ids and expected fact ids from the snapshot contents instead
of hardcoding them, so the tests would fail if the function returned canned
values instead of actually judging the conditions.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from mvp_contracts.models import ConditionState, EvidenceSnapshot, Gap, ReviewAction
from mvp_decision.rules import (
    AmbiguousScopeError,
    ConflictingBindingError,
    UnparseableTimeError,
    evaluate_demo_bind_time,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "contracts" / "0.2.1-mvp"


def _load_snapshot(name: str) -> EvidenceSnapshot:
    payload = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
    return EvidenceSnapshot.model_validate(payload["snapshots"][-1])


def _facts_by_predicate(snapshot: EvidenceSnapshot, predicate: str):
    return [f for f in snapshot.admitted_facts if f.predicate == predicate]


def _bound_time_fact(snapshot: EvidenceSnapshot, binding_fact):
    return next(
        f
        for f in _facts_by_predicate(snapshot, "certificate_not_after")
        if f.artifact_id == binding_fact.value
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
    snapshot: EvidenceSnapshot,
    *,
    gap_id: str = "GAP-TIME-001",
    asset_id: str | None = None,
    environment: str | None = None,
    link_id: str | None = None,
) -> EvidenceSnapshot:
    """Attach a certificate_time gap, optionally scoped to another object/环境/链路."""
    binding_fact = next(
        f for f in snapshot.admitted_facts if f.predicate == "service_uses_certificate"
    )
    updates: dict[str, str] = {}
    if asset_id is not None:
        updates["asset_id"] = asset_id
    if environment is not None:
        updates["environment"] = environment
    if link_id is not None:
        updates["link_id"] = link_id
    scope = (
        binding_fact.scope
        if not updates
        else binding_fact.scope.model_copy(update=updates)
    )
    gap = Gap(
        schema_version=snapshot.schema_version,
        id=gap_id,
        target_condition="certificate_time",
        reason_code="MISSING_NOT_AFTER",
        scope=scope,
        description="缺少已绑定证书的到期时间",
    )
    return snapshot.model_copy(update={"gaps": snapshot.gaps + [gap]})


def _with_binding_gap(
    snapshot: EvidenceSnapshot,
    *,
    gap_id: str = "GAP-BIND-STALE",
    environment: str | None = None,
    link_id: str | None = None,
    valid_to=None,
) -> EvidenceSnapshot:
    """Attach a binding gap, optionally scoped to another 环境/链路 or historical."""
    binding_fact = next(
        f for f in snapshot.admitted_facts if f.predicate == "service_uses_certificate"
    )
    updates: dict = {}
    if environment is not None:
        updates["environment"] = environment
    if link_id is not None:
        updates["link_id"] = link_id
    if valid_to is not None:
        updates["valid_to"] = valid_to
    scope = (
        binding_fact.scope
        if not updates
        else binding_fact.scope.model_copy(update=updates)
    )
    gap = Gap(
        schema_version=snapshot.schema_version,
        id=gap_id,
        target_condition="binding",
        reason_code="MISSING_BINDING",
        scope=scope,
        description="陈旧的绑定缺口，不应满足证书时间缺口",
    )
    return snapshot.model_copy(update={"gaps": snapshot.gaps + [gap]})


def _move_time_fact_to_other_environment(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
    """Move the admitted certificate_not_after fact (and its candidate) to STAGING.

    This creates a synthetic object whose facts span two environments (binding in
    PROD, time in STAGING), which a single ``Decision`` cannot express.
    """

    def move(f):
        return f.model_copy(
            update={"scope": f.scope.model_copy(update={"environment": "STAGING"})}
        )

    return snapshot.model_copy(
        update={
            "admitted_facts": [
                move(f) if f.predicate == "certificate_not_after" else f
                for f in snapshot.admitted_facts
            ],
            "candidates": [
                move(c) if c.predicate == "certificate_not_after" else c
                for c in snapshot.candidates
            ],
        }
    )


class DemoBindTimeRuleTest(unittest.TestCase):
    def test_complete_snapshot_supports_binding_and_certificate_time(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id
        time_fact = _bound_time_fact(snapshot, binding_fact)

        states, support_ids, gap_ids = evaluate_demo_bind_time(snapshot, object_id)

        self.assertEqual(states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(states["certificate_time"], ConditionState.SUPPORTED)
        # Both the binding fact and the bound certificate's time fact are cited,
        # in the original order they appear in the snapshot.
        self.assertIn(binding_fact.id, support_ids)
        self.assertIn(time_fact.id, support_ids)
        self.assertLess(
            support_ids.index(binding_fact.id), support_ids.index(time_fact.id)
        )
        self.assertEqual(gap_ids, [])

    def test_missing_binding_is_unknown_and_only_lists_config_path(self):
        snapshot = _load_snapshot("missing_binding.json")
        path_fact = _facts_by_predicate(snapshot, "configured_certificate_path")[0]
        object_id = path_fact.scope.asset_id

        states, support_ids, gap_ids = evaluate_demo_bind_time(snapshot, object_id)

        self.assertEqual(states["binding"], ConditionState.UNKNOWN)
        self.assertEqual(states["certificate_time"], ConditionState.UNKNOWN)
        # Only the admitted configured-certificate-path fact may be cited.
        self.assertEqual(support_ids, [path_fact.id])

        # The unbound certificate's *candidate* time fact must not be cited.
        candidate_time_id = next(
            c.id for c in snapshot.candidates if c.predicate == "certificate_not_after"
        )
        self.assertNotIn(candidate_time_id, support_ids)

        missing_gap = next(
            g for g in snapshot.gaps if g.reason_code == "MISSING_BINDING"
        )
        self.assertIn(missing_gap.id, gap_ids)

    def test_certificate_time_refuted_when_evaluation_after_not_after(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id
        time_fact = _bound_time_fact(snapshot, binding_fact)

        not_after = datetime.fromisoformat(time_fact.value)
        moved = snapshot.model_copy(
            update={"evaluation_time": not_after + timedelta(days=1)}
        )

        states, support_ids, _gap_ids = evaluate_demo_bind_time(moved, object_id)

        # The decision must come from the snapshot's evaluation_time, not the
        # wall clock: today is before the not_after value, so a system-time read
        # would (wrongly) keep it SUPPORTED.
        self.assertEqual(states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(states["certificate_time"], ConditionState.REFUTED)
        self.assertIn(time_fact.id, support_ids)

    def test_binding_without_confirmation_event_is_not_supported(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        stripped = [
            (
                f.model_copy(update={"review_event_id": None})
                if f.predicate == "service_uses_certificate"
                else f
            )
            for f in snapshot.admitted_facts
        ]
        modified = snapshot.model_copy(update={"admitted_facts": stripped})

        states, _support_ids, _gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.UNKNOWN)
        self.assertEqual(states["certificate_time"], ConditionState.UNKNOWN)

    def test_binding_to_missing_certificate_is_not_supported(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id
        missing_cert = "EVD-CERT-404"

        modified = snapshot.model_copy(
            update={
                "admitted_facts": [
                    (
                        f.model_copy(update={"value": missing_cert})
                        if f.predicate == "service_uses_certificate"
                        else f
                    )
                    for f in snapshot.admitted_facts
                ],
                "candidates": [
                    (
                        c.model_copy(update={"value": missing_cert})
                        if c.predicate == "service_uses_certificate"
                        else c
                    )
                    for c in snapshot.candidates
                ],
            }
        )

        states, _support_ids, _gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.UNKNOWN)
        self.assertEqual(states["certificate_time"], ConditionState.UNKNOWN)

    def test_conflicting_bindings_raise_error(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        # A second certificate, plus a second confirmed binding to the same
        # object pointing at that different certificate.
        original_cert = next(a for a in snapshot.artifacts if a.id == binding_fact.value)
        cert2 = original_cert.model_copy(update={"id": "EVD-CERT-003"})

        bind_candidate = next(
            c for c in snapshot.candidates if c.predicate == "service_uses_certificate"
        )
        candidate2 = bind_candidate.model_copy(
            update={"id": "CAND-BIND-003", "value": cert2.id}
        )
        fact2 = binding_fact.model_copy(
            update={
                "id": "FACT-BIND-003",
                "candidate_id": candidate2.id,
                "value": cert2.id,
                "review_event_id": "REV-BIND-003",
            }
        )
        confirm_event = next(
            e
            for e in snapshot.review_events
            if e.action is ReviewAction.CONFIRM_BINDING
        )
        event2 = confirm_event.model_copy(
            update={"id": "REV-BIND-003", "target_candidate_id": candidate2.id}
        )

        modified = snapshot.model_copy(
            update={
                "artifacts": snapshot.artifacts + [cert2],
                "candidates": snapshot.candidates + [candidate2],
                "admitted_facts": snapshot.admitted_facts + [fact2],
                "review_events": snapshot.review_events + [event2],
            }
        )

        with self.assertRaises(ConflictingBindingError):
            evaluate_demo_bind_time(modified, object_id)

    def test_unparseable_or_naive_not_after_raises(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id
        naive = "2026-12-31T23:59:59"  # missing the UTC "Z" suffix

        modified = snapshot.model_copy(
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

        with self.assertRaises(UnparseableTimeError):
            evaluate_demo_bind_time(modified, object_id)

    def test_bound_without_time_collects_certificate_time_gap(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        modified = _with_certificate_time_gap(_strip_time_fact(snapshot))

        states, _support_ids, gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(states["certificate_time"], ConditionState.UNKNOWN)
        self.assertEqual(gap_ids, ["GAP-TIME-001"])

    def test_certificate_time_gap_not_collected_when_binding_unknown(self):
        snapshot = _load_snapshot("missing_binding.json")
        path_fact = _facts_by_predicate(snapshot, "configured_certificate_path")[0]
        object_id = path_fact.scope.asset_id

        time_gap = Gap(
            schema_version=snapshot.schema_version,
            id="GAP-TIME-002",
            target_condition="certificate_time",
            reason_code="MISSING_NOT_AFTER",
            scope=path_fact.scope,
            description="缺少到期时间",
        )
        modified = snapshot.model_copy(update={"gaps": snapshot.gaps + [time_gap]})

        states, _support_ids, gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.UNKNOWN)
        missing_binding_gap = next(
            g for g in modified.gaps if g.reason_code == "MISSING_BINDING"
        )
        self.assertEqual(gap_ids, [missing_binding_gap.id])
        self.assertNotIn("GAP-TIME-002", gap_ids)

    def test_certificate_time_gap_for_other_object_not_collected(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id  # APP-01

        modified = _with_certificate_time_gap(
            _strip_time_fact(snapshot), asset_id="APP-OTHER"
        )

        states, _support_ids, gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(states["certificate_time"], ConditionState.UNKNOWN)
        self.assertEqual(gap_ids, [])

    def test_certificate_time_gap_for_other_environment_raises_ambiguity(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        modified = _with_certificate_time_gap(
            _strip_time_fact(snapshot), environment="STAGING"
        )

        with self.assertRaises(AmbiguousScopeError):
            evaluate_demo_bind_time(modified, object_id)

    def test_binding_gap_not_collected_when_binding_supported(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        modified = _with_binding_gap(_strip_time_fact(snapshot))

        states, _support_ids, gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(states["certificate_time"], ConditionState.UNKNOWN)
        self.assertEqual(gap_ids, [])

    def test_object_spanning_environments_raises_ambiguity(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        modified = _move_time_fact_to_other_environment(snapshot)

        with self.assertRaises(AmbiguousScopeError):
            evaluate_demo_bind_time(modified, object_id)

    def test_gap_in_other_environment_raises_ambiguity(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        modified = _with_binding_gap(snapshot, environment="STAGING")

        with self.assertRaises(AmbiguousScopeError):
            evaluate_demo_bind_time(modified, object_id)

    def test_historical_gap_in_other_environment_does_not_cause_ambiguity(self):
        snapshot = _load_snapshot("complete.json")
        binding_fact = _facts_by_predicate(snapshot, "service_uses_certificate")[0]
        object_id = binding_fact.scope.asset_id

        past = snapshot.evaluation_time - timedelta(days=1)
        modified = _with_binding_gap(snapshot, environment="STAGING", valid_to=past)

        states, _support_ids, gap_ids = evaluate_demo_bind_time(modified, object_id)

        self.assertEqual(states["binding"], ConditionState.SUPPORTED)
        self.assertEqual(states["certificate_time"], ConditionState.SUPPORTED)
        self.assertEqual(gap_ids, [])


if __name__ == "__main__":
    unittest.main()
