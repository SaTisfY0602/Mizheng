"""The two hand-off examples are executable contracts, not prose snippets."""

import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from mvp_contracts.models import (
    AdmittedFact,
    Artifact,
    BundleManifest,
    CandidateFact,
    Decision,
    EvidenceSnapshot,
    ParseRequest,
    ParseResult,
    ReportArtifact,
    ReviewEvent,
    VerifyResult,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "contracts" / "0.2.1-mvp"
STAGES = {
    "artifacts": Artifact,
    "parse_requests": ParseRequest,
    "parse_results": ParseResult,
    "review_events": ReviewEvent,
    "snapshots": EvidenceSnapshot,
    "decisions": Decision,
    "reports": ReportArtifact,
    "bundles": BundleManifest,
    "verification_results": VerifyResult,
}


class ContractExamplesTest(unittest.TestCase):
    def test_both_examples_round_trip_through_shared_types(self):
        for name in ("complete.json", "missing_binding.json"):
            with self.subTest(name=name):
                payload = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
                for stage, model_type in STAGES.items():
                    self.assertTrue(payload[stage], stage)
                    for item in payload[stage]:
                        instance = model_type.model_validate(item)
                        self.assertEqual(
                            instance,
                            model_type.model_validate_json(instance.model_dump_json()),
                        )

    def test_complete_example_has_traceable_unique_decision(self):
        payload = json.loads((EXAMPLES / "complete.json").read_text(encoding="utf-8"))
        snapshot = EvidenceSnapshot.model_validate(payload["snapshots"][-1])
        decision = Decision.model_validate(payload["decisions"][-1])
        fact_ids = {fact.id for fact in snapshot.admitted_facts}
        self.assertEqual(decision.snapshot_id, snapshot.id)
        self.assertEqual(decision.possible_labels, [decision.proposed_label])
        self.assertTrue(set(decision.support_fact_ids) <= fact_ids)

    def test_missing_binding_is_unknown_and_not_a_negative_fact(self):
        payload = json.loads((EXAMPLES / "missing_binding.json").read_text(encoding="utf-8"))
        snapshot = EvidenceSnapshot.model_validate(payload["snapshots"][0])
        decision = Decision.model_validate(payload["decisions"][0])
        self.assertEqual(decision.condition_states["binding"], "UNKNOWN")
        self.assertIsNone(decision.proposed_label)
        self.assertFalse(any(f.predicate == "service_uses_certificate" for f in snapshot.admitted_facts))

    def test_bad_anchor_and_naive_time_are_rejected(self):
        payload = json.loads((EXAMPLES / "complete.json").read_text(encoding="utf-8"))
        fact = payload["snapshots"][-1]["admitted_facts"][0]
        fact["anchor"]["artifact_id"] = "EVD-WRONG"
        with self.assertRaises(ValidationError):
            AdmittedFact.model_validate(fact)
        candidate = payload["parse_results"][0]["candidates"][0]
        candidate["scope"]["as_of"] = "2026-09-24T10:00:00"
        with self.assertRaises(ValidationError):
            CandidateFact.model_validate(candidate)

    def test_snapshot_rejects_admitted_value_that_differs_from_candidate(self):
        payload = json.loads((EXAMPLES / "complete.json").read_text(encoding="utf-8"))
        snapshot = payload["snapshots"][-1]
        snapshot["admitted_facts"][0]["value"] = "EVD-ANOTHER-CERT"
        with self.assertRaises(ValidationError):
            EvidenceSnapshot.model_validate(snapshot)

    def test_snapshot_rejects_unrecorded_human_confirmation(self):
        payload = json.loads((EXAMPLES / "complete.json").read_text(encoding="utf-8"))
        snapshot = payload["snapshots"][-1]
        snapshot["review_events"] = []
        with self.assertRaises(ValidationError):
            EvidenceSnapshot.model_validate(snapshot)

    def test_pending_decision_cannot_claim_a_unique_label(self):
        payload = json.loads((EXAMPLES / "missing_binding.json").read_text(encoding="utf-8"))
        decision = payload["decisions"][0]
        decision["possible_labels"] = ["COMPLIANT"]
        with self.assertRaises(ValidationError):
            Decision.model_validate(decision)

    def test_failed_parse_cannot_publish_candidates(self):
        payload = json.loads((EXAMPLES / "complete.json").read_text(encoding="utf-8"))
        result = payload["parse_results"][0]
        result["status"] = "FAILED"
        result["errors"] = [{"code":"E_PARSE_FAILED","stage":"PARSE","artifact_id":"EVD-CONF-001","message":"无法解析","retryable":False}]
        with self.assertRaises(ValidationError):
            ParseResult.model_validate(result)

    def test_snapshot_rejects_candidate_from_another_project(self):
        payload = json.loads((EXAMPLES / "missing_binding.json").read_text(encoding="utf-8"))
        snapshot = payload["snapshots"][0]
        snapshot["candidates"][1]["scope"]["project_id"] = "PRJ-OTHER"
        with self.assertRaises(ValidationError):
            EvidenceSnapshot.model_validate(snapshot)

    def test_bundle_rejects_parent_directory_file_name(self):
        payload = json.loads((EXAMPLES / "complete.json").read_text(encoding="utf-8"))
        bundle = payload["bundles"][0]
        bundle["files"]["../outside"] = "a" * 64
        with self.assertRaises(ValidationError):
            BundleManifest.model_validate(bundle)


if __name__ == "__main__":
    unittest.main()
