"""成员三拥有的证据包导出器（实现 ``BundleExporter`` 接口）。

本文件同时给出 ``任务对接.md`` TD-04 里待确认项的落地口径：

* 清单固定为包根目录下的 ``manifest.json``，按共享 ``BundleManifest`` 写入；
* ``manifest.files`` 覆盖证据包内**除 manifest.json 本身以外**的全部文件
  —— 既不产生循环摘要，也不漏保护文件；
* 键是 POSIX 风格的包内相对路径，值是文件的**真实 SM3**（分块读取计算）；
* ``BundleManifest.rule_sm3`` 记录本次运行**真实使用**的规则包摘要（对规则数据
  文件按名排序求 SM3），核验端据此判断规则实现是否仍是产出该包时的那一套；
* ``BundleManifest.id`` 由注入的 ``IdAllocator`` 生成，核验器据此回填
  ``VerifyResult.bundle_id``，与占位值 ``UNKNOWN_BUNDLE_ID`` 区分开；
* 本轮只支持**目录**形式的证据包，归档（zip）留待后续版本；
* 导出前校验报告的实际摘要与 ``ReportArtifact.sm3`` 一致，避免清单记录一个
  与文件内容不符的摘要。
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import (
    BundleManifest,
    Decision,
    EvidenceSnapshot,
    ReportArtifact,
)
from mvp_rules import rule_pack_sm3

from .digest import sm3_of_file
from .report import Clock, utc_now

MANIFEST_NAME = "manifest.json"
BUNDLE_ID_PREFIX = "BND"
SNAPSHOT_DIR = "snapshot"
DECISION_DIR = "decisions"


class BundleExportError(RuntimeError):
    """证据包无法安全导出时抛出（目标目录不安全、报告摘要不符等）。"""


class BundleExporter:
    """把快照、判定和报告写成一个可被独立核验器读取的目录。"""

    def __init__(
        self,
        id_allocator: IdAllocator,
        *,
        bundle_root: Path,
        report_file: Path,
        extra_files: Mapping[str, Path] | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self._id_allocator = id_allocator
        self._bundle_root = Path(bundle_root)
        self._report_file = Path(report_file)
        self._extra_files = dict(extra_files or {})
        self._clock = clock
        for relative in self._extra_files:
            _require_safe_relative_path(relative)

    @property
    def bundle_root(self) -> Path:
        return self._bundle_root

    def export_bundle(
        self,
        snapshot: EvidenceSnapshot,
        decisions: Sequence[Decision],
        report: ReportArtifact,
    ) -> BundleManifest:
        _verify_report_digest(self._report_file, report)
        self._prepare_root()

        shutil.copyfile(self._report_file, self._bundle_root / report.file_name)
        _write_snapshot(self._bundle_root, snapshot)
        _write_decisions(self._bundle_root, decisions)
        self._copy_extra_files()

        files = _collect_file_digests(self._bundle_root)
        manifest = BundleManifest(
            schema_version=snapshot.schema_version,
            id=self._id_allocator.allocate(
                prefix=BUNDLE_ID_PREFIX, project_id=snapshot.project_id
            ),
            snapshot_id=snapshot.id,
            rule_version=report_rule_version(snapshot),
            # 本次运行**真实使用**的规则包摘要，不是占位值：核验端据此判断规则是否
            # 仍是产出该包时的那一套，不一致就拒绝重放。
            rule_sm3=rule_pack_sm3(),
            decision_ids=[decision.id for decision in decisions],
            report_id=report.id,
            files=files,
            created_at=self._clock(),
        )
        (self._bundle_root / MANIFEST_NAME).write_text(
            manifest.model_dump_json(indent=2), encoding="utf-8"
        )
        return manifest

    def _prepare_root(self) -> None:
        """重建包目录；只在目录为空或确实是本工具产出时覆盖。"""
        root = self._bundle_root
        if root.exists():
            if not root.is_dir():
                raise BundleExportError(f"证据包路径不是目录：{root}")
            entries = list(root.iterdir())
            if entries and not (root / MANIFEST_NAME).exists():
                raise BundleExportError(
                    f"目标目录非空且不含 {MANIFEST_NAME}，拒绝覆盖：{root}"
                )
            shutil.rmtree(root)
        root.mkdir(parents=True)

    def _copy_extra_files(self) -> None:
        for relative, source in self._extra_files.items():
            if not source.is_file():
                raise BundleExportError(f"附加材料不存在：{source}")
            target = self._bundle_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)


def report_rule_version(snapshot: EvidenceSnapshot) -> str:
    """清单里的规则版本取自快照，保证判定、报告和清单三者一致。"""
    return snapshot.rule_version


def _write_snapshot(root: Path, snapshot: EvidenceSnapshot) -> None:
    directory = root / SNAPSHOT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{snapshot.id}.json").write_text(
        snapshot.model_dump_json(indent=2), encoding="utf-8"
    )


def _write_decisions(root: Path, decisions: Sequence[Decision]) -> None:
    directory = root / DECISION_DIR
    directory.mkdir(parents=True, exist_ok=True)
    for decision in decisions:
        (directory / f"{decision.id}.json").write_text(
            decision.model_dump_json(indent=2), encoding="utf-8"
        )


def _collect_file_digests(root: Path) -> dict[str, str]:
    """列出包内除清单自身以外的全部文件及其真实 SM3。"""
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST_NAME:
            continue
        files[relative] = sm3_of_file(path)
    return files


def _verify_report_digest(report_file: Path, report: ReportArtifact) -> None:
    if not report_file.is_file():
        raise BundleExportError(f"报告文件不存在：{report_file}")
    actual = sm3_of_file(report_file)
    if actual != report.sm3:
        raise BundleExportError(
            f"报告摘要与 ReportArtifact 记录不一致：期望 {report.sm3}，实际 {actual}"
        )


def _require_safe_relative_path(relative: str) -> None:
    """附加材料路径必须是安全的包内相对路径，避免写出包目录。"""
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or ":" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise BundleExportError(f"附加材料路径必须是安全的相对路径：{relative!r}")


def default_clock() -> Clock:
    """返回默认时钟，供调用方显式复用。"""
    factory: Callable[[], datetime] = utc_now
    return factory
