"""Minimal standalone evidence-bundle verifier.

Member two owns this side too. :class:`BundleVerifier` checks only the file
integrity of a local evidence bundle directory, using the temporary hand-off
layout agreed for integration:

    <bundle_path>/manifest.json  -- JSON valid under ``BundleManifest``
    manifest.files               -- ``{relative path: SM3 of that file's bytes}``

The manifest deliberately does not list itself (no circular digest). This module
reads the directory independently — no database, no model lookups. It also
**replays the fixed rules** over the snapshot stored inside the bundle and
compares the result with the recorded decisions semantically: decision IDs are
re-allocated during replay, so they are not compared. That is what makes
``replay_status`` meaningful rather than a constant.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mvp_contracts.models import (
    BundleManifest,
    CheckStatus,
    Decision,
    ErrorItem,
    EvidenceSnapshot,
    RulePack,
    VerifyResult,
)

from .engine import DecisionEngine
from mvp_rules import default_rule_set, rule_pack_sm3

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
# 重放相关：完整性不通过时拒绝重放，重放缺输入或结果不一致也明确失败
E_REPLAY_BUNDLE_INCOMPLETE = "E_REPLAY_BUNDLE_INCOMPLETE"
E_REPLAY_INPUT_MISSING = "E_REPLAY_INPUT_MISSING"
E_REPLAY_FAILED = "E_REPLAY_FAILED"
E_REPLAY_MISMATCH = "E_REPLAY_MISMATCH"
# 规则指纹不符：清单记录的规则版本或摘要与当前安装环境不一致，拒绝重放
E_REPLAY_RULE_MISMATCH = "E_REPLAY_RULE_MISMATCH"

_CHUNK_SIZE = 1024 * 1024  # 1 MiB 分块读取，避免把大文件整体载入内存


class BundleVerifier:
    """独立核验本地证据包：先查文件完整性，再用规则重放一次判定。"""

    def verify(self, bundle_path: Path) -> VerifyResult:
        errors: list[ErrorItem] = []
        manifest = _load_manifest(bundle_path, errors)
        bundle_id = manifest.id if manifest is not None else PLACEHOLDER_BUNDLE_ID

        integrity_status = (
            _check_files(bundle_path, manifest, errors)
            if manifest is not None
            else CheckStatus.FAIL
        )

        if integrity_status is CheckStatus.PASS and manifest is not None:
            replay_status, replay_errors = _replay(bundle_path, manifest)
        else:
            # 包被改动过就不重放：否则可能拿被篡改的快照算出「一致」的假象
            replay_status = CheckStatus.FAIL
            replay_errors = [
                _error(
                    E_REPLAY_BUNDLE_INCOMPLETE,
                    "证据包完整性未通过，拒绝重放判定",
                )
            ]
        errors.extend(replay_errors)

        return VerifyResult(
            schema_version="0.2.1-mvp",
            bundle_id=bundle_id,
            integrity_status=integrity_status,
            replay_status=replay_status,
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


def _replay(
    bundle_path: Path, manifest: BundleManifest
) -> tuple[CheckStatus, list[ErrorItem]]:
    """用规则重新计算一次判定，与证据包里记录的判定做语义比对。

    独立核验器不连接数据库、不调用模型；重放只依赖证据包内的快照、判定与规则实现。
    判定 ID 是重新分配的，因此比对忽略 ID，只比对象、条件状态、可能结论、建议标签、
    工作流状态、支持事实与缺口引用。
    """
    # 规则指纹先于一切重放动作核对：清单记录的规则版本与摘要必须仍是**安装环境里
    # 这一套**。放在输入检查之前，是因为这是环境级问题——哪怕包本身不完整，也应该
    # 先告诉核验者「你手上的规则不对」，而不是让他去查包的输入。
    mismatch = _check_rule_fingerprint(manifest)
    if mismatch is not None:
        return CheckStatus.FAIL, [mismatch]

    snapshot = _load_snapshot(bundle_path, manifest)
    if snapshot is None:
        return CheckStatus.FAIL, [
            _error(E_REPLAY_INPUT_MISSING, "证据包里没有与清单匹配的快照，无法重放")
        ]

    recorded = _load_decisions(bundle_path)
    if not recorded:
        return CheckStatus.FAIL, [
            _error(E_REPLAY_INPUT_MISSING, "证据包里没有判定记录，无法比对重放结果")
        ]

    try:
        rule_pack = RulePack(
            schema_version=snapshot.schema_version,
            id="RP-REPLAY",
            version=snapshot.rule_version,
            # 用当前安装环境的真实规则摘要构造，而不是占位值。
            sm3=rule_pack_sm3(),
            rule_ids=sorted({decision.rule_id for decision in recorded}),
        )
        replayed = DecisionEngine(_ReplayIdAllocator()).evaluate(snapshot, rule_pack)
    except Exception as exc:  # 规则无法重放本身就是核验失败
        return CheckStatus.FAIL, [
            _error(
                E_REPLAY_FAILED,
                f"规则重放无法完成：{type(exc).__name__}: {exc}",
            )
        ]

    if _semantic(replayed) != _semantic(recorded):
        return CheckStatus.FAIL, [
            _error(
                E_REPLAY_MISMATCH,
                "重放结果与证据包中记录的判定不一致，判定可能被改写或规则已变更",
            )
        ]
    return CheckStatus.PASS, []


def _check_rule_fingerprint(manifest: BundleManifest) -> ErrorItem | None:
    """核对清单里的规则版本与真实摘要；不一致返回错误，一致返回 ``None``。

    两条都要核，理由不同：

    * ``rule_version`` 说明这批判定是按哪一版规则口径做的；当前规则包不接受的
      版本无法重放。
    * ``rule_sm3`` 说明规则**内容**没被换过；只比版本号挡不住「版本号没动但规则
      文件被改」这种情况。
    """
    rule_set = default_rule_set()
    if manifest.rule_version not in rule_set.accepted_versions:
        return _error(
            E_REPLAY_RULE_MISMATCH,
            f"证据包记录的规则版本 {manifest.rule_version} 不在当前规则包接受的版本集合 "
            f"{sorted(rule_set.accepted_versions)} 内，无法确认重放口径",
        )
    current = rule_pack_sm3(rule_set)
    if manifest.rule_sm3 != current:
        return _error(
            E_REPLAY_RULE_MISMATCH,
            f"规则包内容与证据包记录不一致：包内 rule_sm3={manifest.rule_sm3[:12]}…，"
            f"当前规则包={current[:12]}…；规则实现已变更，拒绝用新规则重放旧包",
        )
    return None


class _ReplayIdAllocator:
    """重放专用分配器：ID 会与原件不同，所以比对时刻意忽略 ID。"""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, str], int] = {}

    def allocate(self, *, prefix: str, project_id: str) -> str:
        key = (prefix, project_id)
        self._counters[key] = self._counters.get(key, 0) + 1
        return f"REPLAY-{prefix}-{project_id}-{self._counters[key]:04d}"


def _load_snapshot(bundle_path: Path, manifest: BundleManifest) -> EvidenceSnapshot | None:
    directory = bundle_path / "snapshot"
    if not directory.is_dir():
        return None
    for path in sorted(directory.glob("*.json")):
        try:
            snapshot = EvidenceSnapshot.model_validate_json(path.read_bytes())
        except Exception:
            continue
        if snapshot.id == manifest.snapshot_id:
            return snapshot
    return None


def _load_decisions(bundle_path: Path) -> list[Decision]:
    directory = bundle_path / "decisions"
    if not directory.is_dir():
        return []
    decisions: list[Decision] = []
    for path in sorted(directory.glob("*.json")):
        try:
            decisions.append(Decision.model_validate_json(path.read_bytes()))
        except Exception:
            continue
    return decisions


def _semantic(decisions: list[Decision]) -> list[tuple]:
    """判定的语义指纹，刻意不含 ID。"""
    return sorted(
        (
            decision.object_id,
            decision.rule_id,
            decision.rule_version,
            tuple(
                sorted(
                    (name, str(state))
                    for name, state in decision.condition_states.items()
                )
            ),
            tuple(str(label) for label in decision.possible_labels),
            str(decision.proposed_label)
            if decision.proposed_label is not None
            else None,
            str(decision.workflow_status),
            tuple(sorted(decision.support_fact_ids)),
            tuple(sorted(decision.gap_ids)),
        )
        for decision in decisions
    )


def _error(code: str, message: str) -> ErrorItem:
    return ErrorItem(code=code, stage=STAGE, artifact_id=None, message=message)
