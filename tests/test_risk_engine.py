"""风险规则引擎测试：规则口径、排除项处理，以及「可解释、可溯源」这条硬要求。

真实材料造不出弱签名证书（cryptography 50.x 拒绝 SHA-1 签名），所以弱签名/弱密钥
两类规则用「真实快照 + 定点改写事实值」的方式覆盖，其余走真实材料端到端。
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.models import EvidenceSnapshot

from mvp_flow import IdAllocator, run_case
from mvp_flow.pipeline import MODE_REAL
from mvp_risk import RiskEngine, RiskSeverity

FIXED_NOW = datetime(2026, 9, 28, 0, 0, 0, tzinfo=timezone.utc)


class RiskRulesTest(unittest.TestCase):
    def test_complete_case_has_no_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            findings = RiskEngine(IdAllocator()).evaluate(snapshot)

            self.assertEqual(findings, [])

    def test_missing_binding_reports_binding_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("missing_binding", Path(tmp))
            findings = RiskEngine(IdAllocator()).evaluate(snapshot)

            self.assertEqual([f.rule_id for f in findings], ["RISK-BINDING-UNKNOWN"])
            self.assertIs(findings[0].severity, RiskSeverity.MEDIUM)
            self.assertEqual(findings[0].object_id, "APP-02")

    def test_risky_case_reports_expected_risks_in_severity_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("risky", Path(tmp))
            findings = RiskEngine(IdAllocator()).evaluate(snapshot)

            self.assertEqual(
                sorted(f.rule_id for f in findings),
                [
                    "RISK-CERT-EXPIRING",
                    "RISK-CERT-PURPOSE-MISSING",
                    "RISK-CERT-SAN-MISMATCH",
                    "RISK-CERT-SELF-SIGNED",
                    "RISK-CERT-WEAK-KEY",
                    "RISK-TLS-WEAK-CIPHER",
                    "RISK-TLS-WEAK-PROTOCOL",
                ],
            )
            # 高风险排在前面
            self.assertEqual(
                [f.severity for f in findings],
                [RiskSeverity.HIGH] * 5 + [RiskSeverity.MEDIUM] * 2,
            )

    def test_trusted_chain_is_not_reported(self):
        """complete 用的是根 CA 签发的叶证书，既不该报自签也不该报签发者缺失。"""
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            rule_ids = {f.rule_id for f in RiskEngine(IdAllocator()).evaluate(snapshot)}

            self.assertNotIn("RISK-CERT-SELF-SIGNED", rule_ids)
            self.assertNotIn("RISK-CERT-UNTRUSTED-ISSUER", rule_ids)

    def test_untrusted_issuer_when_ca_certificate_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            # 把根 CA 的候选整个拿掉，等价于「材料里没提供签发者证书」
            ca_ids = {
                artifact.id
                for artifact in snapshot.artifacts
                if artifact.original_name == "root-ca.pem"
            }
            self.assertTrue(ca_ids)
            patched = snapshot.model_copy(
                update={
                    "candidates": [
                        candidate
                        for candidate in snapshot.candidates
                        if candidate.artifact_id not in ca_ids
                    ]
                }
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [
                f for f in findings if f.rule_id == "RISK-CERT-UNTRUSTED-ISSUER"
            ]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.HIGH)

    def test_not_yet_valid_certificate_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            # 生效时间晚于核查时间（2026-09-24）
            patched = _patch_facts(
                snapshot, "certificate_not_before", "2026-12-01T00:00:00Z"
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [f for f in findings if f.rule_id == "RISK-CERT-NOT-YET-VALID"]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.HIGH)

    def test_eku_without_server_auth_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            patched = _patch_facts(
                snapshot, "certificate_extended_key_usage", ["clientAuth"]
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [
                f for f in findings if f.rule_id == "RISK-CERT-EKU-NOT-SERVER-AUTH"
            ]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.HIGH)

    def test_wildcard_san_matches_subdomain(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            # app.example.cn 应被 *.example.cn 覆盖
            patched = _patch_facts(
                snapshot, "certificate_san_dns", ["*.example.cn"]
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            self.assertNotIn("RISK-CERT-SAN-MISMATCH", {f.rule_id for f in findings})

    def test_weak_signature_rule_fires_on_patched_fact(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            patched = _patch_facts(
                snapshot, "certificate_signature_algorithm", "sha1WithRSAEncryption"
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            self.assertIn(
                "RISK-CERT-WEAK-SIGNATURE", {f.rule_id for f in findings}
            )

    def test_unknown_signature_algorithm_is_reported_as_low(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            patched = _patch_facts(
                snapshot, "certificate_signature_algorithm", "unknown_oid:1.2.3.4"
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [f for f in findings if f.rule_id == "RISK-CERT-SIGNATURE-UNKNOWN"]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.LOW)

    def test_excluded_cipher_is_not_reported_as_weak(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("risky", Path(tmp))
            # `!aNULL` 是排除项，`HIGH` 不含弱标记，都不该触发弱套件风险
            patched = _patch_facts(
                snapshot, "configured_cipher_suites", ["HIGH", "!aNULL"]
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            self.assertNotIn("RISK-TLS-WEAK-CIPHER", {f.rule_id for f in findings})

    def test_strong_protocols_are_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("risky", Path(tmp))
            patched = _patch_facts(
                snapshot, "configured_tls_protocols", ["TLSv1.2", "TLSv1.3"]
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            self.assertNotIn("RISK-TLS-WEAK-PROTOCOL", {f.rule_id for f in findings})

    def test_expired_certificate_is_high_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            # complete 的核查时间是 2026-09-24，把到期时间改到它之前
            patched = _patch_facts(
                snapshot, "certificate_not_after", "2026-09-01T00:00:00Z"
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [f for f in findings if f.rule_id == "RISK-CERT-EXPIRED"]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.HIGH)
            # 已过期就不该再报「即将到期」
            self.assertNotIn("RISK-CERT-EXPIRING", {f.rule_id for f in findings})

    def test_unparsable_expiry_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            patched = _patch_facts(
                snapshot, "certificate_not_after", "不是时间"
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [
                f for f in findings if f.rule_id == "RISK-CERT-TIME-UNPARSABLE"
            ]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.MEDIUM)

    def test_missing_expiry_fact_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("complete", Path(tmp))
            patched = snapshot.model_copy(
                update={
                    "admitted_facts": [
                        fact
                        for fact in snapshot.admitted_facts
                        if fact.predicate != "certificate_not_after"
                    ]
                }
            )

            findings = RiskEngine(IdAllocator()).evaluate(patched)

            matched = [f for f in findings if f.rule_id == "RISK-CERT-TIME-MISSING"]
            self.assertEqual(len(matched), 1)
            self.assertIs(matched[0].severity, RiskSeverity.MEDIUM)

    def test_findings_are_traceable_and_actionable(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("risky", Path(tmp))
            findings = RiskEngine(IdAllocator()).evaluate(snapshot)

            self.assertTrue(findings)
            known_fact_ids = {fact.id for fact in snapshot.admitted_facts}
            for finding in findings:
                with self.subTest(rule_id=finding.rule_id):
                    self.assertTrue(finding.id.startswith("RISK-"))
                    self.assertTrue(finding.title)
                    self.assertTrue(finding.description)
                    # 每条风险都要给出整改建议
                    self.assertTrue(finding.remediation)
                    # 引用的依据必须真的在快照里
                    self.assertTrue(
                        set(finding.evidence_fact_ids) <= known_fact_ids
                    )

    def test_findings_are_deterministic_for_same_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = _real_snapshot("risky", Path(tmp))

            first = RiskEngine(IdAllocator()).evaluate(snapshot)
            second = RiskEngine(IdAllocator()).evaluate(snapshot)

            self.assertEqual(
                [f.to_dict() for f in first], [f.to_dict() for f in second]
            )


def _real_snapshot(case_name: str, output_root: Path) -> EvidenceSnapshot:
    """跑一次真实模式，把证据包里定稿的快照读回来。"""
    record = run_case(
        case_name, output_root=output_root, now=FIXED_NOW, mode=MODE_REAL
    )
    path = Path(record.bundle_path) / "snapshot" / f"{record.snapshot_id}.json"
    return EvidenceSnapshot.model_validate_json(path.read_text(encoding="utf-8"))


def _patch_facts(
    snapshot: EvidenceSnapshot, predicate: str, value: object
) -> EvidenceSnapshot:
    """把某个谓词的准入事实值改写掉，用于覆盖造不出来的材料情形。"""
    patched = [
        fact.model_copy(update={"value": value}) if fact.predicate == predicate else fact
        for fact in snapshot.admitted_facts
    ]
    return snapshot.model_copy(update={"admitted_facts": patched})


if __name__ == "__main__":
    unittest.main()
