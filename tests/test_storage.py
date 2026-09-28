"""受控材料存储层的测试：路径安全、SM3 真实性、与 Artifact 契约的衔接。

这些测试用真实文件与真实 SM3，不依赖任何虚构摘要；重点验证「上传文件名不参与
路径计算」和「材料引用不能越出存储根目录」这两条硬约定。
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.models import Artifact

from mvp_flow.digest import sm3_of_file
from mvp_flow.id_allocator import IdAllocator
from mvp_flow.storage import MaterialStorageError, MaterialStore

FIXED_NOW = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)


class MaterialStoreTest(unittest.TestCase):
    def test_import_returns_real_digest_and_key_ignores_original_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MaterialStore(root / "materials")
            source = root / "nginx.conf"
            payload = b"server { ssl_certificate /etc/ssl/app.pem; }\n"
            source.write_bytes(payload)

            stored = store.import_material(
                project_id="PRJ-001",
                artifact_id="EVD-CONF-001",
                original_name="nginx.conf",
                source=source,
            )

            self.assertEqual(stored.storage_key, "PRJ-001/EVD-CONF-001")
            self.assertEqual(stored.byte_size, len(payload))
            self.assertEqual(stored.sm3, sm3_of_file(source))
            self.assertEqual(len(stored.sm3), 64)
            # 材料落在项目目录下，文件名与上传名无关
            resolved = store.resolve(stored.storage_key)
            self.assertEqual(resolved.name, "EVD-CONF-001")
            self.assertEqual(resolved.read_bytes(), payload)

    def test_stored_material_builds_a_valid_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MaterialStore(root / "materials")
            source = root / "app.pem"
            source.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")

            allocator = IdAllocator()
            artifact_id = allocator.allocate(prefix="EVD", project_id="PRJ-001")
            stored = store.import_material(
                project_id="PRJ-001",
                artifact_id=artifact_id,
                original_name="app.pem",
                source=source,
            )
            artifact = Artifact(
                id=artifact_id,
                project_id="PRJ-001",
                kind="CERTIFICATE",
                format="X509_PEM",
                original_name=stored.original_name,
                sm3=stored.sm3,
                byte_size=stored.byte_size,
                storage_key=stored.storage_key,
                imported_at=FIXED_NOW,
            )

            self.assertEqual(artifact.storage_key, stored.storage_key)
            self.assertEqual(artifact.sm3, sm3_of_file(source))

    def test_duplicate_import_is_refused_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MaterialStore(root / "materials")
            first = root / "a.conf"
            second = root / "b.conf"
            first.write_text("原始材料", encoding="utf-8")
            second.write_text("试图覆盖", encoding="utf-8")

            store.import_material(
                project_id="PRJ-001",
                artifact_id="EVD-CONF-001",
                original_name="a.conf",
                source=first,
            )
            with self.assertRaises(MaterialStorageError):
                store.import_material(
                    project_id="PRJ-001",
                    artifact_id="EVD-CONF-001",
                    original_name="b.conf",
                    source=second,
                )
            # 原文件内容未被改写
            self.assertEqual(
                store.resolve("PRJ-001/EVD-CONF-001").read_text(encoding="utf-8"),
                "原始材料",
            )

    def test_original_name_with_separators_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MaterialStore(root / "materials")
            source = root / "a.conf"
            source.write_text("x", encoding="utf-8")

            for bad_name in ("../evil.conf", "sub/evil.conf", "C:evil.conf", "sub\\evil.conf"):
                with self.subTest(name=bad_name):
                    with self.assertRaises(MaterialStorageError):
                        store.import_material(
                            project_id="PRJ-001",
                            artifact_id="EVD-CONF-001",
                            original_name=bad_name,
                            source=source,
                        )

    def test_resolve_rejects_traversal_and_absolute_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MaterialStore(Path(tmp) / "materials")
            outside = Path(tmp) / "outside.conf"
            outside.write_text("不该被读到", encoding="utf-8")

            for bad_key in (
                "../outside.conf",
                "PRJ-001/../../outside.conf",
                "/etc/passwd",
                "C:/Windows/win.ini",
                "PRJ-001\\EVD-CONF-001",
                "PRJ-001",
                "PRJ-001/",
                "./PRJ-001/EVD-CONF-001",
            ):
                with self.subTest(key=bad_key):
                    with self.assertRaises(MaterialStorageError):
                        store.resolve(bad_key)

    def test_missing_material_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MaterialStore(Path(tmp) / "materials")
            with self.assertRaises(MaterialStorageError):
                store.resolve("PRJ-001/EVD-CONF-999")
            self.assertFalse(store.exists("PRJ-001/EVD-CONF-999"))
            self.assertFalse(store.exists("../etc/passwd"))

    def test_import_requires_a_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = MaterialStore(root / "materials")
            with self.assertRaises(MaterialStorageError):
                store.import_material(
                    project_id="PRJ-001",
                    artifact_id="EVD-CONF-001",
                    original_name="dir.conf",
                    source=root,
                )


if __name__ == "__main__":
    unittest.main()
