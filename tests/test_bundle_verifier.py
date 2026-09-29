"""Tests for the standalone evidence-bundle integrity verifier.

These tests exercise :class:`mvp_decision.BundleVerifier` against real files in
a temporary directory, using real SM3 digests computed with ``hashlib.new("sm3")``.
They never depend on the sample snapshots' fabricated digests. These bundles
contain no ``snapshot/`` or ``decisions/``, so replay legitimately fails with
``E_REPLAY_INPUT_MISSING`` while integrity passes.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.models import BundleManifest, CheckStatus
from mvp_rules import rule_pack_sm3

from mvp_decision import BundleVerifier
from mvp_decision.verifier import (
    E_BUNDLE_DIGEST_MISMATCH,
    E_BUNDLE_FILE_MISSING,
    E_BUNDLE_FILE_NOT_REGULAR,
    E_BUNDLE_MANIFEST_INVALID,
    E_BUNDLE_MANIFEST_MISSING,
    E_BUNDLE_NO_FILES,
    E_BUNDLE_PATH_ESCAPE,
    E_REPLAY_INPUT_MISSING,
    E_REPLAY_RULE_MISMATCH,
    PLACEHOLDER_BUNDLE_ID,
)

# Well-known SM3 test vector for the ASCII string "abc".
SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def _sm3(data: bytes) -> str:
    digest = hashlib.new("sm3")
    digest.update(data)
    return digest.hexdigest()


def _write_manifest(bundle: Path, files: dict[str, str], *, rule_sm3: str | None = None) -> None:
    manifest = BundleManifest(
        id="BND-TEST",
        snapshot_id="FS-TEST",
        rule_version="demo-0.2.0",
        # 默认写当前安装环境的真实规则摘要，让完整性用例能走到重放阶段；
        # 需要构造「规则不一致」的失败用例时显式传入别的值。
        rule_sm3=rule_sm3 if rule_sm3 is not None else rule_pack_sm3(),
        decision_ids=["DEC-TEST"],
        report_id="RPT-TEST",
        files=files,
        created_at=datetime(2026, 9, 26, 0, 0, 0, tzinfo=timezone.utc),
    )
    (bundle / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")


def _make_link(link: Path, target: Path) -> bool:
    """Create a link escaping the bundle dir; returns False if the OS forbids it.

    Prefers a directory symlink, then falls back to a Windows directory junction
    (``mklink /J``), which does not require administrator privileges.
    """
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except OSError:
        pass
    if os.name == "nt":
        run = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
        )
        return run.returncode == 0
    return False


class BundleVerifierTest(unittest.TestCase):
    def test_correct_sm3_yields_integrity_pass(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            (bundle / "artifacts").mkdir(parents=True)
            content = b"hello world"
            (bundle / "artifacts" / "nginx.conf").write_bytes(content)
            _write_manifest(bundle, {"artifacts/nginx.conf": _sm3(content)})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.PASS)
            self.assertEqual(result.bundle_id, "BND-TEST")
            # 这个包没有 snapshot/decisions，重放只能报「缺输入」
            self.assertEqual(
                [e.code for e in result.errors], [E_REPLAY_INPUT_MISSING]
            )
            self.assertEqual(result.replay_status, CheckStatus.FAIL)

    def test_known_sm3_test_vector(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            (bundle / "abc.txt").write_text("abc", encoding="utf-8")
            _write_manifest(bundle, {"abc.txt": SM3_ABC})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.PASS)

    def test_replay_fails_when_snapshot_and_decisions_are_missing(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            content = b"payload"
            (bundle / "f.bin").write_bytes(content)
            _write_manifest(bundle, {"f.bin": _sm3(content)})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.PASS)
            # 完整性通过，但没有可重放的输入——不能因为「没得比」就给 PASS
            self.assertEqual(result.replay_status, CheckStatus.FAIL)
            self.assertTrue(any(e.code == E_REPLAY_INPUT_MISSING for e in result.errors))

    def test_rule_digest_mismatch_refuses_replay(self):
        """规则实现变了就不许用新规则给旧包背书。

        这是本项检查存在的理由：只比版本号挡不住「版本号没动、规则文件被换」。
        """
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            content = b"payload"
            (bundle / "f.bin").write_bytes(content)
            # 清单记录一个与当前规则包不同的摘要（仍是合法的 64 位十六进制）
            _write_manifest(bundle, {"f.bin": _sm3(content)}, rule_sm3="0" * 64)

            result = BundleVerifier().verify(bundle)

            # 文件本身没被动过，完整性还是 PASS
            self.assertEqual(result.integrity_status, CheckStatus.PASS)
            self.assertEqual(result.replay_status, CheckStatus.FAIL)
            self.assertEqual([e.code for e in result.errors], [E_REPLAY_RULE_MISMATCH])
            self.assertIn("规则包内容与证据包记录不一致", result.errors[0].message)

    def test_unaccepted_rule_version_refuses_replay(self):
        """记录了一个当前规则包不接受的版本号时，无法确认重放口径。"""
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            content = b"payload"
            (bundle / "f.bin").write_bytes(content)
            _write_manifest(bundle, {"f.bin": _sm3(content)})

            manifest_path = bundle / "manifest.json"
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload["rule_version"] = "9999.0-not-a-real-version"
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.replay_status, CheckStatus.FAIL)
            self.assertEqual([e.code for e in result.errors], [E_REPLAY_RULE_MISMATCH])

    def test_matching_rule_fingerprint_does_not_block_replay(self):
        """指纹一致时不应被这条检查挡住（后面失败只因为缺快照/判定）。"""
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            content = b"payload"
            (bundle / "f.bin").write_bytes(content)
            _write_manifest(bundle, {"f.bin": _sm3(content)})

            result = BundleVerifier().verify(bundle)

            codes = [e.code for e in result.errors]
            self.assertNotIn(E_REPLAY_RULE_MISMATCH, codes)
            self.assertIn(E_REPLAY_INPUT_MISSING, codes)

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            _write_manifest(bundle, {"nope.txt": "a" * 64})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertTrue(any(e.code == E_BUNDLE_FILE_MISSING for e in result.errors))

    def test_tampered_content_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            (bundle / "f.txt").write_bytes(b"original")
            _write_manifest(bundle, {"f.txt": _sm3(b"original")})
            (bundle / "f.txt").write_bytes(b"tampered")

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertTrue(
                any(e.code == E_BUNDLE_DIGEST_MISMATCH for e in result.errors)
            )

    def test_invalid_manifest_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            (bundle / "manifest.json").write_text("{ not valid json", encoding="utf-8")

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertEqual(result.bundle_id, PLACEHOLDER_BUNDLE_ID)
            self.assertTrue(
                any(e.code == E_BUNDLE_MANIFEST_INVALID for e in result.errors)
            )

    def test_missing_manifest_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertEqual(result.bundle_id, PLACEHOLDER_BUNDLE_ID)
            self.assertTrue(
                any(e.code == E_BUNDLE_MANIFEST_MISSING for e in result.errors)
            )

    def test_empty_file_list_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            _write_manifest(bundle, {})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertTrue(any(e.code == E_BUNDLE_NO_FILES for e in result.errors))

    def test_directory_listed_as_file_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            (bundle / "subdir").mkdir(parents=True)
            _write_manifest(bundle, {"subdir": "b" * 64})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertTrue(
                any(e.code == E_BUNDLE_FILE_NOT_REGULAR for e in result.errors)
            )

    def test_path_escape_via_symlink_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("secret", encoding="utf-8")
            bundle = root / "bundle"
            bundle.mkdir()
            if not _make_link(bundle / "link", outside):
                self.skipTest("当前环境无法创建符号链接或目录联接")
            _write_manifest(bundle, {"link": _sm3(b"secret")})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.FAIL)
            self.assertTrue(any(e.code == E_BUNDLE_PATH_ESCAPE for e in result.errors))


if __name__ == "__main__":
    unittest.main()
