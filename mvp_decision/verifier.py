"""Minimal standalone evidence-bundle verifier.

Member two owns this side too. :class:`BundleVerifier` checks only the file
integrity of a local evidence bundle directory, using the temporary hand-off
layout agreed for integration:

    <bundle_path>/manifest.json  -- JSON valid under ``BundleManifest``
    manifest.files               -- ``{relative path: SM3 of that file's bytes}``

The manifest deliberately does not list itself (no circular digest). This module
reads the directory independently — no database, no model lookups, no decision
engine — and does not replay rules: ``replay_status`` is always ``FAIL`` until
rule replay is implemented. The full bundle format and the exporter still need
to be coordinated with member three.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mvp_contracts.models import (
    BundleManifest,
    CheckStatus,
    ErrorItem,
    VerifyResult,
)

MANIFEST_NAME = "manifest.json"
PLACEHOLDER_BUNDLE_ID = "UNKNOWN_BUNDLE_ID"
STAGE = "VERIFY"

# 稳定的英文机器错误码：说明当前真正检查了什么、尚未检查什么。
E_BUNDLE_MANIFEST_MISSING = "E_BUNDLE_MANIFEST_MISSING"
E_BUNDLE_MANIFEST_INVALID = "E_BUNDLE_MANIFEST_INVALID"
E_BUNDLE_NO_FILES = "E_BUNDLE_NO_FILES"
E_BUNDLE_FILE_MISSING = "E_BUNDLE_FILE_MISSING"
E_BUNDLE_FILE_NOT_REGULAR = "E_BUNDLE_FILE_NOT_REGULAR"
E_BUNDLE_PATH_ESCAPE = "E_BUNDLE_PATH_ESCAPE"
E_BUNDLE_FILE_READ_FAILED = "E_BUNDLE_FILE_READ_FAILED"
E_BUNDLE_DIGEST_MISMATCH = "E_BUNDLE_DIGEST_MISMATCH"
E_REPLAY_NOT_IMPLEMENTED = "E_REPLAY_NOT_IMPLEMENTED"

_CHUNK_SIZE = 1024 * 1024  # 1 MiB 分块读取，避免把大文件整体载入内存


class BundleVerifier:
    """独立核验本地证据包目录的文件完整性；不重放规则。"""

    def verify(self, bundle_path: Path) -> VerifyResult:
        errors: list[ErrorItem] = []
        manifest = _load_manifest(bundle_path, errors)
        bundle_id = manifest.id if manifest is not None else PLACEHOLDER_BUNDLE_ID

        integrity_status = (
            _check_files(bundle_path, manifest, errors)
            if manifest is not None
            else CheckStatus.FAIL
        )

        # 规则重放尚未实现：即使完整性通过，重放状态也必须是 FAIL，
        # 不得照抄样例中的 PASS。
        errors.append(_replay_not_implemented())

        return VerifyResult(
            schema_version="0.2.0-mvp",
            bundle_id=bundle_id,
            integrity_status=integrity_status,
            replay_status=CheckStatus.FAIL,
            errors=errors,
        )


def _load_manifest(bundle_path: Path, errors: list[ErrorItem]) -> BundleManifest | None:
    manifest_path = bundle_path / MANIFEST_NAME
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        errors.append(
            ErrorItem(
                code=E_BUNDLE_MANIFEST_MISSING,
                stage=STAGE,
                artifact_id=None,
                message=f"清单 {MANIFEST_NAME} 不存在或无法读取：{exc}",
            )
        )
        return None
    try:
        return BundleManifest.model_validate_json(raw)
    except Exception as exc:
        errors.append(
            ErrorItem(
                code=E_BUNDLE_MANIFEST_INVALID,
                stage=STAGE,
                artifact_id=None,
                message=f"清单 {MANIFEST_NAME} 不是合法的 BundleManifest：{exc}",
            )
        )
        return None


def _check_files(
    bundle_path: Path, manifest: BundleManifest, errors: list[ErrorItem]
) -> CheckStatus:
    if not manifest.files:
        errors.append(
            ErrorItem(
                code=E_BUNDLE_NO_FILES,
                stage=STAGE,
                artifact_id=None,
                message="清单未列出任何待核验文件",
            )
        )
        return CheckStatus.FAIL

    base = bundle_path.resolve()
    ok = True
    for rel, expected in manifest.files.items():
        if not _verify_file(base, rel, expected, errors):
            ok = False
    return CheckStatus.PASS if ok else CheckStatus.FAIL


def _verify_file(base: Path, rel: str, expected: str, errors: list[ErrorItem]) -> bool:
    candidate = base / rel
    resolved = candidate.resolve()

    # 目录穿越或符号链接逃逸：解析后必须仍位于证据包目录内。
    if not resolved.is_relative_to(base):
        errors.append(
            ErrorItem(
                code=E_BUNDLE_PATH_ESCAPE,
                stage=STAGE,
                artifact_id=rel,
                message=f"文件路径越出证据包目录：{rel}",
            )
        )
        return False

    # 即便符号链接指向包内，也拒绝核验，保证只处理真实普通文件。
    if _has_symlink(base, rel):
        errors.append(
            ErrorItem(
                code=E_BUNDLE_PATH_ESCAPE,
                stage=STAGE,
                artifact_id=rel,
                message=f"文件路径包含符号链接，拒绝核验：{rel}",
            )
        )
        return False

    if not resolved.exists():
        errors.append(
            ErrorItem(
                code=E_BUNDLE_FILE_MISSING,
                stage=STAGE,
                artifact_id=rel,
                message=f"清单列出的文件不存在：{rel}",
            )
        )
        return False

    if not resolved.is_file():
        errors.append(
            ErrorItem(
                code=E_BUNDLE_FILE_NOT_REGULAR,
                stage=STAGE,
                artifact_id=rel,
                message=f"清单列出的路径不是普通文件：{rel}",
            )
        )
        return False

    actual = _sm3_of(resolved, rel, errors)
    if actual is None:
        return False
    if actual != expected:
        errors.append(
            ErrorItem(
                code=E_BUNDLE_DIGEST_MISMATCH,
                stage=STAGE,
                artifact_id=rel,
                message=f"SM3 摘要不符：{rel}（期望 {expected}，实际 {actual}）",
            )
        )
        return False
    return True


def _has_symlink(base: Path, rel: str) -> bool:
    current = base
    for part in Path(rel).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _sm3_of(path: Path, rel: str, errors: list[ErrorItem]) -> str | None:
    try:
        digest = hashlib.new("sm3")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        errors.append(
            ErrorItem(
                code=E_BUNDLE_FILE_READ_FAILED,
                stage=STAGE,
                artifact_id=rel,
                message=f"读取文件失败：{rel}（{exc}）",
            )
        )
        return None


def _replay_not_implemented() -> ErrorItem:
    return ErrorItem(
        code=E_REPLAY_NOT_IMPLEMENTED,
        stage=STAGE,
        artifact_id=None,
        message="规则重放核验尚未实现，未重放任何判定",
    )
