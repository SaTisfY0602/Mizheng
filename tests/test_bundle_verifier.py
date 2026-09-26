"""Tests for the standalone evidence-bundle integrity verifier.

These tests exercise :class:`mvp_decision.BundleVerifier` against real files in
a temporary directory, using real SM3 digests computed with ``hashlib.new("sm3")``.
They never depend on the sample snapshots' fabricated digests. The verifier is
expected to check file integrity only: ``replay_status`` must stay ``FAIL`` even
when integrity passes.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.models import BundleManifest, CheckStatus

from mvp_decision import BundleVerifier
from mvp_decision.verifier import (
    E_BUNDLE_DIGEST_MISMATCH,
    E_BUNDLE_FILE_MISSING,
    E_BUNDLE_FILE_NOT_REGULAR,
    E_BUNDLE_MANIFEST_INVALID,
    E_BUNDLE_MANIFEST_MISSING,
    E_BUNDLE_NO_FILES,
    E_BUNDLE_PATH_ESCAPE,
    E_REPLAY_NOT_IMPLEMENTED,
    PLACEHOLDER_BUNDLE_ID,
)

# Well-known SM3 test vector for the ASCII string "abc".
SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def _sm3(data: bytes) -> str:
    digest = hashlib.new("sm3")
    digest.update(data)
    return digest.hexdigest()


def _write_manifest(bundle: Path, files: dict[str, str]) -> None:
    manifest = BundleManifest(
        id="BND-TEST",
        snapshot_id="FS-TEST",
        rule_version="demo-0.2.0",
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
            # Integrity passed, so the only recorded error is the replay one.
            self.assertEqual(
                [e.code for e in result.errors], [E_REPLAY_NOT_IMPLEMENTED]
            )

    def test_known_sm3_test_vector(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            (bundle / "abc.txt").write_text("abc", encoding="utf-8")
            _write_manifest(bundle, {"abc.txt": SM3_ABC})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.PASS)

    def test_integrity_pass_but_replay_still_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle"
            bundle.mkdir()
            content = b"payload"
            (bundle / "f.bin").write_bytes(content)
            _write_manifest(bundle, {"f.bin": _sm3(content)})

            result = BundleVerifier().verify(bundle)

            self.assertEqual(result.integrity_status, CheckStatus.PASS)
            self.assertEqual(result.replay_status, CheckStatus.FAIL)
            self.assertTrue(any(e.code == E_REPLAY_NOT_IMPLEMENTED for e in result.errors))

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
