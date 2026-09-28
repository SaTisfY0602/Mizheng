"""成员三模块：流程编排、ID 分配、报告生成与证据包导出。

对外入口以 ``mvp_contracts/interfaces.py`` 为准：
``IdAllocator`` 与 ``BundleExporter`` 由本包实现；``Parser``、``EvidenceBuilder``、
``DecisionEngine``、``BundleVerifier`` 由成员一、二提供，本包只调用不复制。
"""

from .digest import sm3_of_bytes, sm3_of_file
from .exporter import MANIFEST_NAME, BundleExportError, BundleExporter
from .id_allocator import IdAllocator, IdAllocatorError, require_identifier
from .pipeline import (
    CASE_FILES,
    CASE_ORDER,
    REAL,
    SKIPPED,
    SUCCEEDED,
    TEST_DOUBLE,
    RunRecord,
    SnapshotFixtureLoader,
    StageRecord,
    run_all,
    run_case,
)
from .report import ReportBuildResult, ReportBuilder
from .storage import MaterialStorageError, MaterialStore, StoredMaterial

__all__ = [
    "CASE_FILES",
    "CASE_ORDER",
    "MANIFEST_NAME",
    "REAL",
    "SKIPPED",
    "SUCCEEDED",
    "TEST_DOUBLE",
    "BundleExportError",
    "BundleExporter",
    "IdAllocator",
    "IdAllocatorError",
    "MaterialStorageError",
    "MaterialStore",
    "ReportBuildResult",
    "ReportBuilder",
    "RunRecord",
    "SnapshotFixtureLoader",
    "StageRecord",
    "StoredMaterial",
    "require_identifier",
    "run_all",
    "run_case",
    "sm3_of_bytes",
    "sm3_of_file",
]
