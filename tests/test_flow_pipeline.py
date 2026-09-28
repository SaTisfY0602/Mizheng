"""成员三流程的端到端测试：两组样例 + 证据包被改动后能被发现。

这些测试不依赖任何虚构摘要：证据包是真实写出的目录，摘要由 ``hashlib.new("sm3")``
现算，核验走成员二的独立核验器。快照仍来自契约样例（这是本阶段的既定替身），所以
测试只断言**流程与判定语义**，不声称真实材料已被测评。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.models import CheckStatus, Decision, EvidenceSnapshot, ReportArtifact
from mvp_decision import BundleVerifier

from mvp_flow import BundleExportError, BundleExporter, IdAllocator, run_all, run_case
from mvp_flow.digest import sm3_of_file

FIXED_NOW = datetime(2026, 9, 28, 0, 0, 0, tzinfo=timezone.utc)


class FlowPipelineTest(unittest.TestCase):
    def test_complete_case_reaches_unique_compliant_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case("complete", output_root=Path(tmp), now=FIXED_NOW)

            self.assertEqual(record.overall_status, "SUCCEEDED")
            self.assertEqual(record.conclusion_state, "EVALUATED")
            self.assertTrue(all(stage.status == "SUCCEEDED" for stage in record.stages))

            payload = _report_payload(record.report_path)
            self.assertEqual(
                payload["summary"],
                {
                    "decision_count": 1,
                    "evaluated": 1,
                    "pending_evidence": 0,
                    "conflict": 0,
                },
            )
            decision = payload["decisions"][0]
            self.assertEqual(decision["proposed_label"], "COMPLIANT")
            self.assertEqual(decision["possible_labels"], ["COMPLIANT"])
            self.assertEqual(decision["gaps"], [])
            self.assertEqual(payload["follow_up_requests"], [])

            # 独立核验：文件完整性通过，规则重放应与记录一致
            self.assertEqual(record.verification["integrity_status"], "PASS")
            self.assertEqual(record.verification["replay_status"], "PASS")
            self.assertEqual(record.verification["errors"], [])
            self.assertEqual(
                record.verification["bundle_id"], _manifest_id(record.bundle_path)
            )

    def test_missing_binding_case_stays_pending_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case("missing_binding", output_root=Path(tmp), now=FIXED_NOW)

            self.assertEqual(record.overall_status, "SUCCEEDED")
            self.assertEqual(record.conclusion_state, "PENDING_EVIDENCE")

            payload = _report_payload(record.report_path)
            decision = payload["decisions"][0]
            self.assertIsNone(decision["proposed_label"])
            self.assertEqual(decision["condition_states"]["binding"], "UNKNOWN")
            self.assertEqual(
                decision["possible_labels"], ["COMPLIANT", "PARTIALLY_COMPLIANT"]
            )
            self.assertEqual(decision["workflow_status"], "PENDING_EVIDENCE")
            self.assertTrue(decision["gaps"])

            # 报告不得把它写成最终符合
            self.assertEqual(payload["conclusion"]["state"], "PENDING_EVIDENCE")
            self.assertIn("不构成最终符合性判定", payload["conclusion"]["statement"])
            self.assertEqual(
                payload["conclusion"]["pending_objects"], [decision["object_id"]]
            )
            self.assertEqual(payload["conclusion"]["evaluated_objects"], [])

            # 缺口转成补证请求
            requests = payload["follow_up_requests"]
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0]["reason_code"], "MISSING_BINDING")
            self.assertEqual(requests[0]["target_condition"], "binding")
            self.assertEqual(requests[0]["action"], "REQUEST_EVIDENCE")

    def test_tampered_bundle_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case("complete", output_root=Path(tmp), now=FIXED_NOW)
            target = Path(record.bundle_path) / "assessment-draft.json"
            target.write_text(
                target.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )

            result = BundleVerifier().verify(Path(record.bundle_path))
            self.assertIs(result.integrity_status, CheckStatus.FAIL)
            codes = {error.code for error in result.errors}
            self.assertIn("E_BUNDLE_DIGEST_MISMATCH", codes)
            # 除摘要不符外不应出现别的完整性错误
            self.assertEqual(
                {code for code in codes if code.startswith("E_BUNDLE_")},
                {"E_BUNDLE_DIGEST_MISMATCH"},
            )
            # 包被改动过就拒绝重放，不会拿被篡改的快照算出「一致」的假象
            self.assertIn("E_REPLAY_BUNDLE_INCOMPLETE", codes)

    def test_replay_detects_tampered_decision(self):
        """文件与清单被同时改掉时，重放仍要能发现判定与规则重算不一致。"""
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case("complete", output_root=Path(tmp), now=FIXED_NOW)
            bundle = Path(record.bundle_path)
            decision_path = next((bundle / "decisions").glob("*.json"))

            payload = json.loads(decision_path.read_text(encoding="utf-8"))
            payload["proposed_label"] = "NON_COMPLIANT"
            payload["possible_labels"] = ["NON_COMPLIANT"]
            decision_path.write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )

            # 顺手把清单里的摘要也改成新文件的摘要，让完整性检查通过
            _rewrite_manifest_digest(bundle, f"decisions/{decision_path.name}")

            result = BundleVerifier().verify(bundle)

            # 摘要对上 → 完整性通过；但规则重算的结果对不上 → 重放必须失败
            self.assertIs(result.integrity_status, CheckStatus.PASS)
            self.assertIs(result.replay_status, CheckStatus.FAIL)
            self.assertIn(
                "E_REPLAY_MISMATCH", {error.code for error in result.errors}
            )

    def test_replay_fails_when_recorded_rule_is_unsupported(self):
        """判定记录里出现引擎不支持的规则时，重放要明确失败而不是给 PASS。"""
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case("complete", output_root=Path(tmp), now=FIXED_NOW)
            bundle = Path(record.bundle_path)
            decision_path = next((bundle / "decisions").glob("*.json"))

            payload = json.loads(decision_path.read_text(encoding="utf-8"))
            payload["rule_id"] = "UNSUPPORTED-RULE"
            decision_path.write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            _rewrite_manifest_digest(bundle, f"decisions/{decision_path.name}")

            result = BundleVerifier().verify(bundle)

            self.assertIs(result.integrity_status, CheckStatus.PASS)
            self.assertIs(result.replay_status, CheckStatus.FAIL)
            self.assertIn("E_REPLAY_FAILED", {error.code for error in result.errors})

    def test_missing_bundle_file_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case("complete", output_root=Path(tmp), now=FIXED_NOW)
            snapshot_files = sorted((Path(record.bundle_path) / "snapshot").glob("*.json"))
            self.assertTrue(snapshot_files)
            snapshot_files[0].unlink()

            result = BundleVerifier().verify(Path(record.bundle_path))
            self.assertIs(result.integrity_status, CheckStatus.FAIL)
            self.assertIn("E_BUNDLE_FILE_MISSING", {error.code for error in result.errors})
            # 重放状态任何情况下都不得变成 PASS
            self.assertIs(result.replay_status, CheckStatus.FAIL)

    def test_same_input_and_time_reproduce_identical_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = run_case("complete", output_root=Path(tmp) / "a", now=FIXED_NOW)
            second = run_case("complete", output_root=Path(tmp) / "b", now=FIXED_NOW)

            self.assertEqual(first.decision_ids, second.decision_ids)
            self.assertEqual(
                first.verification["bundle_id"], second.verification["bundle_id"]
            )
            self.assertEqual(first.stages[0].detail, second.stages[0].detail)

    def test_run_all_covers_both_cases_in_fixed_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = run_all(output_root=Path(tmp), now=FIXED_NOW)

            self.assertEqual(
                [record.case_name for record in records],
                ["complete", "missing_binding"],
            )
            self.assertEqual(
                [record.conclusion_state for record in records],
                ["EVALUATED", "PENDING_EVIDENCE"],
            )
            for record in records:
                self.assertTrue(Path(record.record_path).is_file())

    def test_export_refuses_unsafe_target_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = run_case("complete", output_root=root, now=FIXED_NOW)
            snapshot, decisions, report = _reload_bundle_inputs(record)

            unsafe = root / "not-ours"
            unsafe.mkdir()
            (unsafe / "keep.txt").write_text("用户数据", encoding="utf-8")

            exporter = BundleExporter(
                IdAllocator(),
                bundle_root=unsafe,
                report_file=Path(record.report_path),
                clock=lambda: FIXED_NOW,
            )
            with self.assertRaises(BundleExportError):
                exporter.export_bundle(snapshot, decisions, report)
            # 拒绝覆盖时不得删掉别人的文件
            self.assertTrue((unsafe / "keep.txt").is_file())

    def test_report_digest_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = run_case("complete", output_root=root, now=FIXED_NOW)
            snapshot, decisions, report = _reload_bundle_inputs(record)

            report_path = Path(record.report_path)
            report_path.write_text('{"tampered": true}', encoding="utf-8")

            exporter = BundleExporter(
                IdAllocator(),
                bundle_root=root / "second-bundle",
                report_file=report_path,
                clock=lambda: FIXED_NOW,
            )
            with self.assertRaises(BundleExportError):
                exporter.export_bundle(snapshot, decisions, report)


class IdAllocatorTest(unittest.TestCase):
    def test_ids_are_unique_per_prefix_and_project(self):
        allocator = IdAllocator()
        first = allocator.allocate(prefix="DEC", project_id="PRJ-001")
        second = allocator.allocate(prefix="DEC", project_id="PRJ-001")
        other_prefix = allocator.allocate(prefix="RPT", project_id="PRJ-001")
        other_project = allocator.allocate(prefix="DEC", project_id="PRJ-002")

        self.assertEqual(first, "DEC-PRJ-001-0001")
        self.assertEqual(second, "DEC-PRJ-001-0002")
        self.assertEqual(len({first, second, other_prefix, other_project}), 4)
        self.assertEqual(allocator.issued_count(prefix="DEC", project_id="PRJ-001"), 2)

    def test_run_token_separates_runs(self):
        allocator = IdAllocator(run_token="R1")
        self.assertEqual(
            allocator.allocate(prefix="DEC", project_id="PRJ-001"), "DEC-PRJ-001-R1-0001"
        )

    def test_invalid_identifiers_are_rejected(self):
        allocator = IdAllocator()
        with self.assertRaises(ValueError):
            allocator.allocate(prefix="", project_id="PRJ-001")
        with self.assertRaises(ValueError):
            allocator.allocate(prefix="DEC", project_id="PRJ 001")


def _rewrite_manifest_digest(bundle: Path, relative: str) -> None:
    """把清单里某个文件的摘要改成它的当前摘要，用于模拟「连清单一起改」的篡改。"""
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][relative] = sm3_of_file(bundle / relative)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )


def _report_payload(report_path: str) -> dict:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))


def _manifest_id(bundle_path: str) -> str:
    manifest = json.loads(
        (Path(bundle_path) / "manifest.json").read_text(encoding="utf-8")
    )
    return manifest["id"]


def _reload_bundle_inputs(
    record,
) -> tuple[EvidenceSnapshot, list[Decision], ReportArtifact]:
    """从运行产物读回契约对象，供导出器边界用例复用。"""
    bundle = Path(record.bundle_path)
    snapshot = EvidenceSnapshot.model_validate_json(
        (bundle / "snapshot" / f"{record.snapshot_id}.json").read_text(encoding="utf-8")
    )
    decisions = [
        Decision.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted((bundle / "decisions").glob("*.json"))
    ]
    report_path = Path(record.report_path)
    report = ReportArtifact(
        schema_version=snapshot.schema_version,
        id="RPT-PRJ-001-9001",
        snapshot_id=snapshot.id,
        decision_ids=[decision.id for decision in decisions],
        unresolved_decision_ids=[],
        file_name=report_path.name,
        sm3=sm3_of_file(report_path),
        created_at=FIXED_NOW,
    )
    return snapshot, decisions, report


if __name__ == "__main__":
    unittest.main()
