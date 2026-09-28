"""真实模式端到端测试：真正解析材料，而不是读样例快照。

这些测试断言的是「解析器真的读到了材料里的信息」，所以会检查候选事实的谓词集合，
而不只是流程状态。同时验证两条边界：无归属的证书候选不得进入准入；单份材料解析失败
不得阻断其他材料的证据。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_flow import run_case
from mvp_flow.pipeline import MODE_REAL
from mvp_rules import default_rule_set

FIXED_NOW = datetime(2026, 9, 28, 0, 0, 0, tzinfo=timezone.utc)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MATERIALS_ROOT = PROJECT_ROOT / "examples" / "materials"


class RealModeTest(unittest.TestCase):
    def test_complete_materials_produce_unique_compliant(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            self.assertEqual(record.mode, "real")
            self.assertEqual(record.overall_status, "SUCCEEDED")
            self.assertEqual(record.conclusion_state, "EVALUATED")

            by_stage = {stage.stage: stage for stage in record.stages}
            for stage in ("import_materials", "parse_materials", "build_snapshot"):
                self.assertEqual(by_stage[stage].implementation, "REAL", stage)
                self.assertEqual(by_stage[stage].status, "SUCCEEDED", stage)

            payload = _report_payload(record.report_path)
            self.assertEqual(payload["decisions"][0]["proposed_label"], "COMPLIANT")
            self.assertEqual(payload["decisions"][0]["gaps"], [])

            snapshot = _snapshot(record)
            predicates = {candidate["predicate"] for candidate in snapshot["candidates"]}
            for expected in (
                "configured_certificate_path",
                "service_uses_certificate",
                "certificate_not_after",
                "certificate_subject",
                "certificate_san_dns",
            ):
                self.assertIn(expected, predicates)

    def test_missing_binding_materials_stay_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "missing_binding", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            self.assertEqual(record.overall_status, "SUCCEEDED")
            self.assertEqual(record.conclusion_state, "PENDING_EVIDENCE")

            snapshot = _snapshot(record)
            self.assertEqual(
                [gap["reason_code"] for gap in snapshot["gaps"]], ["MISSING_BINDING"]
            )

            # 证书材料没能对上配置里的路径 → 它没有对象 → 候选不得进入准入
            certificate_ids = {
                artifact["id"]
                for artifact in snapshot["artifacts"]
                if artifact["kind"] == "CERTIFICATE"
            }
            self.assertTrue(certificate_ids)
            self.assertFalse(
                any(
                    fact["artifact_id"] in certificate_ids
                    for fact in snapshot["admitted_facts"]
                )
            )
            # 也不得产生「未使用该证书」的否定事实
            self.assertFalse(
                any(
                    fact["predicate"] == "service_uses_certificate"
                    for fact in snapshot["admitted_facts"]
                )
            )

    def test_bundle_contains_material_originals(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )
            manifest = json.loads(
                (Path(record.bundle_path) / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertIn("materials/nginx.conf", manifest["files"])
            self.assertIn("materials/app.pem", manifest["files"])
            self.assertNotIn("manifest.json", manifest["files"])

    def test_broken_certificate_does_not_block_config_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            materials = _stage_materials(Path(tmp), "missing_binding")
            # 换成一段不是证书的内容：该文件解析失败，但配置材料的结果必须保留
            (materials / "missing_binding" / "unbound.der").write_bytes(b"not a certificate")

            record = run_case(
                "missing_binding",
                output_root=Path(tmp) / "out",
                materials_dir=materials,
                now=FIXED_NOW,
                mode=MODE_REAL,
            )

            by_stage = {stage.stage: stage for stage in record.stages}
            self.assertEqual(by_stage["parse_materials"].status, "SUCCEEDED")
            self.assertIn("解析错误 1 条", by_stage["parse_materials"].detail)
            self.assertEqual(record.conclusion_state, "PENDING_EVIDENCE")

            snapshot = _snapshot(record)
            self.assertTrue(
                any(
                    fact["predicate"] == "configured_certificate_path"
                    for fact in snapshot["admitted_facts"]
                )
            )
            self.assertEqual(
                [error["code"] for error in snapshot["errors"]], ["E_PARSE_FAILED"]
            )

    def test_real_mode_is_rerunnable_on_the_same_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )
            second = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            # 相同输入 + 相同核查时点 → 相同 ID 与相同证据包
            self.assertEqual(first.snapshot_id, second.snapshot_id)
            self.assertEqual(first.decision_ids, second.decision_ids)
            self.assertEqual(
                first.verification["bundle_id"], second.verification["bundle_id"]
            )


class RulePackWiringTest(unittest.TestCase):
    """流程真实地从版本化规则包组规则包，而不是交一个占位值。"""

    def test_build_rule_pack_stage_is_real_not_a_double(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            by_stage = {stage.stage: stage for stage in record.stages}
            stage = by_stage["build_rule_pack"]
            self.assertEqual(stage.implementation, "REAL")
            self.assertNotIn("占位", stage.detail)

    def test_rule_pack_stage_reports_id_version_and_rule_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            rule_set = default_rule_set()
            self.assertEqual(record.rule_version, rule_set.meta.version)
            detail = next(
                stage.detail for stage in record.stages if stage.stage == "build_rule_pack"
            )
            self.assertIn(rule_set.meta.id, detail)
            expected_rules = rule_set.rules_for_version(rule_set.meta.version)
            self.assertIn(f"{len(expected_rules)} 条规则", detail)
            # 判定条数 = 对象数 × 该版本声明的规则数
            self.assertEqual(len(record.decision_ids), len(expected_rules))

    def test_manifest_records_the_snapshot_rule_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )
            manifest = json.loads(
                (Path(record.bundle_path) / "manifest.json").read_text(encoding="utf-8")
            )

            self.assertEqual(manifest["rule_version"], record.rule_version)
            self.assertEqual(len(manifest["decision_ids"]), len(record.decision_ids))

    def test_independent_verifier_replays_every_rule(self):
        """重放按记录里的 rule_ids 重建规则包，多条规则也要能逐条重算一致。"""
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "complete", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )
            record2 = run_case(
                "risky", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            self.assertEqual(record.verification["replay_status"], "PASS")
            self.assertEqual(record2.verification["replay_status"], "PASS")
            self.assertEqual(record2.verification["errors"], [])

    def test_short_key_case_yields_a_non_compliant_decision(self):
        """risky 样例用的是 1024 位 RSA，判定侧必须给出不符合，而不只是风险提示。"""
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "risky", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            payload = _report_payload(record.report_path)
            by_rule = {d["rule_id"]: d for d in payload["decisions"]}
            strength = by_rule["DEC-CERT-KEY-STRENGTH"]
            self.assertEqual(strength["proposed_label"], "NON_COMPLIANT")

    def test_certificate_without_purpose_extension_pends_for_evidence(self):
        """risky 的证书没有用途扩展：不得判成符合，也不得判成不符合。"""
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "risky", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            payload = _report_payload(record.report_path)
            by_rule = {d["rule_id"]: d for d in payload["decisions"]}
            purpose = by_rule["DEC-CERT-KEY-USAGE"]
            self.assertIsNone(purpose["proposed_label"])
            self.assertEqual(purpose["workflow_status"], "PENDING_EVIDENCE")
            self.assertTrue(purpose["gaps"])
            # 缺口要能落到补证请求上
            codes = {request["reason_code"] for request in payload["follow_up_requests"]}
            self.assertIn("MISSING_CERTIFICATE_EVIDENCE", codes)

    def test_conclusion_objects_are_deduplicated(self):
        """一个对象有多条判定，结论里也只该出现一次。"""
        with tempfile.TemporaryDirectory() as tmp:
            record = run_case(
                "missing_binding", output_root=Path(tmp), now=FIXED_NOW, mode=MODE_REAL
            )

            payload = _report_payload(record.report_path)
            pending = payload["conclusion"]["pending_objects"]
            self.assertEqual(len(pending), len(set(pending)))
            self.assertTrue(len(pending) >= 1)


def _stage_materials(target: Path, *case_names: str) -> Path:
    """把仓库里的演示材料复制到临时目录，便于改动后重跑。"""
    root = target / "materials"
    root.mkdir(parents=True, exist_ok=True)
    for case_name in case_names:
        shutil.copytree(MATERIALS_ROOT / case_name, root / case_name)
    return root


def _snapshot(record) -> dict:
    path = (
        Path(record.bundle_path) / "snapshot" / f"{record.snapshot_id}.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def _report_payload(report_path: str) -> dict:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
