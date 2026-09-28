"""成员三拥有的流程编排：把三个人的模块串成一条可运行链路。

```text
载入材料 → 解析 → 整理证据 → 判定 → 报告 → 导出证据包 → 独立核验
```

两种运行模式
------------
``fixture``（默认）
    直接读契约样例里已定稿的快照，把「解析与证据整理」整个跳过。用于验证接口与流程，
    运行记录里相关阶段标为 ``TEST_DOUBLE``。

``real``
    从 ``examples/materials/<样例名>/`` 读合成材料，走真实链路：受控存储导入 →
    成员一的解析器 → 成员一的证据整理 → 成员二判定 → 成员三报告与证据包 →
    成员二独立核验。这条路径不读任何虚构摘要。

**真实与替身边界**都会写进 ``run-record.json``，演示时按它逐条说明；替身的成功不会
被描述成真实测评通过。
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

from mvp_contracts.models import (
    Artifact,
    ArtifactKind,
    Decision,
    EvidenceSnapshot,
    ParseRequest,
    ParseResult,
    ReviewAction,
    ReviewEvent,
    RulePack,
    Scope,
    VerifyResult,
)
from mvp_decision import BundleVerifier, DecisionEngine
from mvp_parse import (
    EvidenceBuilder,
    NginxConfigParser,
    X509CertificateParser,
    derive_binding_candidates,
)
from mvp_risk import RiskEngine, RiskFinding, RiskSeverity
from mvp_rules import default_rule_set, rule_pack_sm3

from .exporter import BundleExporter
from .id_allocator import IdAllocator
from .report import Clock, ReportBuilder, ReportBuildResult, utc_now
from .storage import MaterialStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXAMPLES_DIR = PROJECT_ROOT / "examples" / "contracts" / "0.2.0-mvp"
DEFAULT_MATERIALS_DIR = PROJECT_ROOT / "examples" / "materials"
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "results"

CASE_FILES = {
    "complete": "complete.json",
    "missing_binding": "missing_binding.json",
}
# 有契约样例、可在 fixture 模式下跑的两组
CONTRACT_CASES = ("complete", "missing_binding")
# 有演示材料、可在 real 模式下跑的三组（risky 故意做差，用于验证风险识别）
REAL_CASES = ("complete", "missing_binding", "risky")
CASE_ORDER = REAL_CASES
CASE_DESCRIPTIONS = {
    "complete": "配置与证书可确认绑定，人工确认后应得到唯一建议",
    "missing_binding": "配置指向无法对应的证书，绑定保持 UNKNOWN，必须停在待补证",
    "risky": "故意启用弱协议、弱套件并使用弱签名/短密钥/临期证书，用于验证风险识别",
}

INTERFACE_VERSION = "0.2.0-mvp"
# 默认判定规则取规则包声明的 DECISION 层；真实值在 _build_rule_pack 里由规则包解析。
RULE_ID = "DEC-BIND-TIME"

NGINX_PARSER_VERSION = "nginx-0.2.0"
X509_PARSER_VERSION = "x509-0.2.0"

MODE_FIXTURE = "fixture"
MODE_REAL = "real"

# 实现性质
REAL = "REAL"
TEST_DOUBLE = "TEST_DOUBLE"

# 阶段状态
SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
SKIPPED = "SKIPPED"

# 归属
MEMBER_ONE = "成员一"
MEMBER_TWO = "成员二"
MEMBER_THREE = "成员三"

_FIXTURE_STAGES: tuple[tuple[str, str, str], ...] = (
    ("load_fixture", TEST_DOUBLE, MEMBER_ONE),
    ("build_rule_pack", TEST_DOUBLE, MEMBER_TWO),
    ("decide", REAL, MEMBER_TWO),
    ("assess_risk", REAL, MEMBER_TWO),
    ("build_report", REAL, MEMBER_THREE),
    ("export_bundle", REAL, MEMBER_THREE),
    ("verify_bundle", REAL, MEMBER_TWO),
)

_REAL_STAGES: tuple[tuple[str, str, str], ...] = (
    ("import_materials", REAL, MEMBER_THREE),
    ("parse_materials", REAL, MEMBER_ONE),
    ("build_snapshot", REAL, MEMBER_ONE),
    ("build_rule_pack", REAL, MEMBER_TWO),
    ("decide", REAL, MEMBER_TWO),
    ("assess_risk", REAL, MEMBER_TWO),
    ("build_report", REAL, MEMBER_THREE),
    ("export_bundle", REAL, MEMBER_THREE),
    ("verify_bundle", REAL, MEMBER_TWO),
)

_CONFIG_SUFFIXES = {".conf", ".cnf"}
_PEM_SUFFIXES = {".pem", ".crt"}
_DER_SUFFIXES = {".der", ".cer"}


@dataclass(frozen=True)
class StageRecord:
    """单个流程阶段的执行记录，含真实/替身边界。"""

    stage: str
    implementation: str
    owner: str
    status: str
    detail: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class RunRecord:
    """一次端到端运行的完整记录，可直接作为对接会的运行证据。"""

    case_name: str
    mode: str
    sample_file: str
    head_commit: str
    interface_version: str
    rule_id: str
    rule_version: str | None
    evaluation_time: str | None
    snapshot_id: str | None
    started_at: str
    finished_at: str
    overall_status: str
    conclusion_state: str | None
    stages: tuple[StageRecord, ...]
    decision_ids: tuple[str, ...]
    report_path: str | None
    bundle_path: str | None
    verification: dict | None
    failure_reason: str | None
    record_path: str | None = None

    def to_dict(self) -> dict:
        payload = dataclasses.asdict(self)
        payload["stages"] = [stage.to_dict() for stage in self.stages]
        return payload


class SnapshotFixtureLoader:
    """测试替身：替代成员一的 ``Parser`` / ``EvidenceBuilder``。

    只从契约样例读取已定稿的快照，不解析任何真实材料。因此它让链路可以先跑通，
    但产出的快照不是真实材料测评结果，运行记录里必须标为 ``TEST_DOUBLE``。
    """

    def __init__(self, examples_dir: Path) -> None:
        self._examples_dir = Path(examples_dir)

    def sample_path(self, case_name: str) -> Path:
        return self._examples_dir / CASE_FILES[case_name]

    def load(self, case_name: str) -> tuple[dict, EvidenceSnapshot]:
        payload = json.loads(self.sample_path(case_name).read_text(encoding="utf-8"))
        snapshot = EvidenceSnapshot.model_validate(payload["snapshots"][-1])
        return payload, snapshot


def run_case(
    case_name: str,
    *,
    output_root: Path | None = None,
    examples_dir: Path | None = None,
    materials_dir: Path | None = None,
    now: datetime | None = None,
    id_allocator: IdAllocator | None = None,
    mode: str = MODE_FIXTURE,
) -> RunRecord:
    """跑通一个样例的完整链路，任何阶段失败都如实记录且不再往下走。"""
    known_cases = sorted(set(CASE_FILES) | set(REAL_CASES))
    if case_name not in known_cases:
        raise ValueError(f"未知样例 {case_name!r}，可选：{known_cases}")
    if mode not in {MODE_FIXTURE, MODE_REAL}:
        raise ValueError(f"未知运行模式 {mode!r}，可选：{MODE_FIXTURE} / {MODE_REAL}")
    if mode == MODE_FIXTURE and case_name not in CASE_FILES:
        raise ValueError(
            f"样例 {case_name!r} 没有对应的契约样例，只能用 {MODE_REAL} 模式运行"
        )

    examples = Path(examples_dir) if examples_dir is not None else DEFAULT_EXAMPLES_DIR
    materials = Path(materials_dir) if materials_dir is not None else DEFAULT_MATERIALS_DIR
    results_root = Path(output_root) if output_root is not None else DEFAULT_RESULTS_DIR
    case_dir = results_root / case_name
    clock: Clock = _fixed_clock(now) if now is not None else utc_now
    allocator = id_allocator if id_allocator is not None else IdAllocator()
    started_at = clock()
    plan = _REAL_STAGES if mode == MODE_REAL else _FIXTURE_STAGES

    stages: list[StageRecord] = []
    decisions: list[Decision] = []
    report_result: ReportBuildResult | None = None
    bundle_path: Path | None = None
    verification: VerifyResult | None = None
    failure_reason: str | None = None

    def add(stage: str, implementation: str, owner: str, status: str, detail: str) -> None:
        stages.append(StageRecord(stage, implementation, owner, status, detail))

    def fail(stage: str, implementation: str, owner: str, exc: BaseException) -> None:
        nonlocal failure_reason
        failure_reason = f"{stage}: {type(exc).__name__}: {exc}"
        add(stage, implementation, owner, FAILED, failure_reason)

    # 1) 载入材料与证据快照
    if mode == MODE_REAL:
        prepared = _prepare_real(case_name, materials, case_dir, clock, allocator, add, fail)
    else:
        prepared = _prepare_fixture(case_name, examples, add, fail)

    if prepared is None:
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, None, [], None, None,
            None, failure_reason, case_dir,
        )
    snapshot, _declared_rule_version = prepared

    # 2) 组规则包（真实：从版本化规则包读取清单与内容摘要）
    try:
        rule_pack = _build_rule_pack(snapshot)
    except Exception as exc:
        fail("build_rule_pack", REAL, MEMBER_TWO, exc)
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, snapshot, [], None, None,
            None, failure_reason, case_dir,
        )
    add(
        "build_rule_pack", REAL, MEMBER_TWO, SUCCEEDED,
        f"规则包 {rule_pack.id} 版本 {rule_pack.version}，"
        f"{len(rule_pack.rule_ids)} 条规则，sm3 {rule_pack.sm3[:12]}…（对规则文件现算）",
    )

    # 3) 判定（真实：成员二引擎 + 成员三 IdAllocator）
    try:
        decisions = DecisionEngine(allocator).evaluate(snapshot, rule_pack)
    except Exception as exc:
        fail("decide", REAL, MEMBER_TWO, exc)
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, snapshot, decisions, None,
            None, None, failure_reason, case_dir,
        )
    add(
        "decide", REAL, MEMBER_TWO, SUCCEEDED,
        f"对象 {[d.object_id for d in decisions]}，判定 ID {[d.id for d in decisions]}",
    )

    # 3.5) 风险识别（真实：规则侧；与判定分开，回答「有什么风险、怎么整改」）
    risk_findings: list[RiskFinding] = []
    try:
        risk_findings = RiskEngine(allocator).evaluate(snapshot)
    except Exception as exc:
        fail("assess_risk", REAL, MEMBER_TWO, exc)
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, snapshot, decisions, None,
            None, None, failure_reason, case_dir,
        )
    add(
        "assess_risk", REAL, MEMBER_TWO, SUCCEEDED,
        f"风险项 {len(risk_findings)} 条（高 "
        f"{_count_severity(risk_findings, RiskSeverity.HIGH)} / 中 "
        f"{_count_severity(risk_findings, RiskSeverity.MEDIUM)} / 低 "
        f"{_count_severity(risk_findings, RiskSeverity.LOW)}）："
        f"{[finding.rule_id for finding in risk_findings] or '无'}",
    )

    # 4) 报告（真实：成员三）
    try:
        report_result = ReportBuilder(allocator, clock=clock).build(
            snapshot,
            decisions,
            case_dir / "report",
            limitations=_limitations(mode, case_name),
            risk_findings=risk_findings,
        )
    except Exception as exc:
        fail("build_report", REAL, MEMBER_THREE, exc)
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, snapshot, decisions, None,
            None, None, failure_reason, case_dir,
        )
    add(
        "build_report", REAL, MEMBER_THREE, SUCCEEDED,
        f"报告 {report_result.report.id}（{report_result.report.file_name}，"
        f"sm3 {report_result.report.sm3[:12]}…），"
        f"未决判定 {len(report_result.report.unresolved_decision_ids)} 个",
    )

    # 5) 导出证据包（真实：成员三）
    bundle_path = case_dir / "bundle"
    try:
        manifest = BundleExporter(
            allocator,
            bundle_root=bundle_path,
            report_file=report_result.path,
            extra_files=_bundle_materials(mode, case_dir, snapshot),
            clock=clock,
        ).export_bundle(snapshot, decisions, report_result.report)
    except Exception as exc:
        fail("export_bundle", REAL, MEMBER_THREE, exc)
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, snapshot, decisions,
            report_result, bundle_path, None, failure_reason, case_dir,
        )
    add(
        "export_bundle", REAL, MEMBER_THREE, SUCCEEDED,
        f"证据包 {manifest.id}，保护文件 {len(manifest.files)} 个"
        f"（{sorted(manifest.files)}），清单不列自身",
    )

    # 6) 独立核验（真实：成员二）
    try:
        verification = BundleVerifier().verify(bundle_path)
    except Exception as exc:
        fail("verify_bundle", REAL, MEMBER_TWO, exc)
        return _finalize(
            case_name, mode, clock, started_at, stages, plan, snapshot, decisions,
            report_result, bundle_path, None, failure_reason, case_dir,
        )
    add(
        "verify_bundle", REAL, MEMBER_TWO, SUCCEEDED,
        f"完整性 {verification.integrity_status}；重放 {verification.replay_status}"
        f"（{', '.join(sorted({e.code for e in verification.errors})) or '无错误'}）",
    )

    return _finalize(
        case_name, mode, clock, started_at, stages, plan, snapshot, decisions,
        report_result, bundle_path, verification, failure_reason, case_dir,
    )


# --------------------------------------------------------------------------- 载入阶段


def _prepare_fixture(
    case_name: str, examples: Path, add, fail
) -> tuple[EvidenceSnapshot, str] | None:
    """替身路径：直接读契约样例里已定稿的快照。"""
    loader = SnapshotFixtureLoader(examples)
    try:
        payload, snapshot = loader.load(case_name)
    except Exception as exc:
        fail("load_fixture", TEST_DOUBLE, MEMBER_ONE, exc)
        return None
    add(
        "load_fixture", TEST_DOUBLE, MEMBER_ONE, SUCCEEDED,
        f"从 {CASE_FILES[case_name]} 读取最后一份快照 {snapshot.id}（替身，非真实解析）",
    )
    del payload
    return snapshot, snapshot.rule_version


def _prepare_real(
    case_name: str,
    materials_root: Path,
    case_dir: Path,
    clock: Clock,
    allocator: IdAllocator,
    add,
    fail,
) -> tuple[EvidenceSnapshot, str] | None:
    """真实路径：受控导入 → 解析 → 证据整理。"""
    case_root = materials_root / case_name
    if not case_root.is_dir():
        fail(
            "import_materials", REAL, MEMBER_THREE,
            FileNotFoundError(f"演示材料目录不存在：{case_root}"),
        )
        return None

    try:
        meta = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        project_id = meta["project_id"]
        evaluation_time = _parse_utc(meta["evaluation_time"])
        scope = Scope(
            project_id=project_id,
            environment=meta["environment"],
            asset_id=meta["asset_id"],
            link_id=meta["link_id"],
            as_of=evaluation_time,
        )
    except Exception as exc:
        fail("import_materials", REAL, MEMBER_THREE, exc)
        return None

    # case_dir 是本次运行的输出目录；先清空，保证材料导入不会撞上上一轮的产物
    if case_dir.exists():
        shutil.rmtree(case_dir)
    store = MaterialStore(case_dir / "materials")

    try:
        artifacts = _import_materials(case_root, store, allocator, project_id, clock)
    except Exception as exc:
        fail("import_materials", REAL, MEMBER_THREE, exc)
        return None
    add(
        "import_materials", REAL, MEMBER_THREE, SUCCEEDED,
        f"受控存储导入 {len(artifacts)} 份材料："
        f"{[(a.id, a.original_name) for a in artifacts]}",
    )

    try:
        parse_results = _parse_materials(artifacts, scope, store, allocator)
    except Exception as exc:
        fail("parse_materials", REAL, MEMBER_ONE, exc)
        return None
    errors = [error for result in parse_results for error in result.errors]
    candidate_count = sum(len(result.candidates) for result in parse_results)
    add(
        "parse_materials", REAL, MEMBER_ONE, SUCCEEDED,
        f"解析 {len(parse_results)} 份材料，候选事实 {candidate_count} 条"
        + (f"，解析错误 {len(errors)} 条（保留其他材料结果）" if errors else "，无错误"),
    )

    try:
        review_events = _review_events(
            case_root, parse_results, allocator, project_id, evaluation_time, meta
        )
        snapshot = EvidenceBuilder(allocator).build_snapshot(
            project_id=project_id,
            evaluation_time=evaluation_time,
            rule_version=meta["rule_version"],
            artifacts=artifacts,
            parse_results=parse_results,
            review_events=review_events,
        )
    except Exception as exc:
        fail("build_snapshot", REAL, MEMBER_ONE, exc)
        return None
    add(
        "build_snapshot", REAL, MEMBER_ONE, SUCCEEDED,
        f"快照 {snapshot.id}：准入事实 {len(snapshot.admitted_facts)} 条，"
        f"缺口 {[gap.reason_code for gap in snapshot.gaps] or '无'}，"
        f"人工事件 {len(review_events)} 条",
    )
    return snapshot, snapshot.rule_version


def _build_rule_pack(snapshot: EvidenceSnapshot) -> RulePack:
    """从版本化规则包组出共享 ``RulePack``。

    * ``version`` 沿用快照的 ``rule_version``——它必须属于规则包接受的版本集合，
      否则判定引擎会显式拒绝，不会拿着不确定版本的规则去算结论；
    * ``rule_ids`` 取规则包为**该版本**声明的判定规则：历史版本样例只带部分事实，
      就跑它支持的规则，不会因为缺字段而产出假阴性；
    * ``sm3`` 是对规则数据文件**现算**的 SM3，不再是占位值，核验端可以据此比对
      规则内容是否被改动。
    """
    rule_set = default_rule_set()
    return RulePack(
        schema_version=snapshot.schema_version,
        id=rule_set.meta.id,
        version=snapshot.rule_version,
        sm3=rule_pack_sm3(rule_set),
        rule_ids=list(rule_set.rules_for_version(snapshot.rule_version)),
    )


def _import_materials(
    case_root: Path,
    store: MaterialStore,
    allocator: IdAllocator,
    project_id: str,
    clock: Clock,
) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted(case_root.iterdir()):
        if not path.is_file() or path.suffix.lower() == ".json":
            continue
        kind, artifact_format = _classify(path)
        artifact_id = allocator.allocate(prefix="EVD", project_id=project_id)
        stored = store.import_material(
            project_id=project_id,
            artifact_id=artifact_id,
            original_name=path.name,
            source=path,
        )
        artifacts.append(
            Artifact(
                id=artifact_id,
                project_id=project_id,
                kind=kind,
                format=artifact_format,
                original_name=stored.original_name,
                sm3=stored.sm3,
                byte_size=stored.byte_size,
                storage_key=stored.storage_key,
                imported_at=clock(),
            )
        )
    return artifacts


def _parse_materials(
    artifacts: list[Artifact], scope: Scope, store: MaterialStore, allocator: IdAllocator
) -> list[ParseResult]:
    config_parser = NginxConfigParser(store=store, id_allocator=allocator)
    certificate_parser = X509CertificateParser(store=store, id_allocator=allocator)

    config_results = [
        config_parser.parse(
            ParseRequest(artifact=artifact, scope=scope, parser_version=NGINX_PARSER_VERSION)
        )
        for artifact in artifacts
        if artifact.kind is ArtifactKind.CONFIG
    ]

    # 证书归属：配置里的路径能对上证书文件名时，才为该证书带上对象；
    # 对不上就保持无对象，交由缺口表达，不猜绑定。
    asset_by_name: dict[str, str] = {}
    for result in config_results:
        for candidate in result.candidates:
            if (
                candidate.predicate == "configured_certificate_path"
                and isinstance(candidate.value, str)
                and candidate.scope.asset_id is not None
            ):
                asset_by_name[_basename(candidate.value)] = candidate.scope.asset_id

    results = list(config_results)
    for artifact in artifacts:
        if artifact.kind is not ArtifactKind.CERTIFICATE:
            continue
        asset_id = asset_by_name.get(artifact.original_name)
        certificate_scope = (
            scope.model_copy(update={"asset_id": asset_id, "link_id": scope.link_id})
            if asset_id is not None
            else scope.model_copy(update={"asset_id": None, "link_id": None})
        )
        results.append(
            certificate_parser.parse(
                ParseRequest(
                    artifact=artifact,
                    scope=certificate_scope,
                    parser_version=X509_PARSER_VERSION,
                )
            )
        )
    # 绑定候选必须在这里派生：人工确认事件的 target 要指向它，而事件在证据整理之前构造
    return derive_binding_candidates(
        project_id=scope.project_id,
        artifacts=artifacts,
        parse_results=results,
        id_allocator=allocator,
    )


def _review_events(
    case_root: Path,
    parse_results: list[ParseResult],
    allocator: IdAllocator,
    project_id: str,
    evaluation_time: datetime,
    meta: dict,
) -> list[ReviewEvent]:
    """把材料目录里的人工确认声明翻译成契约事件（候选 ID 解析后才生成）。"""
    spec_path = case_root / "review_events.json"
    if not spec_path.is_file():
        return []
    specs = json.loads(spec_path.read_text(encoding="utf-8"))
    candidates = [candidate for result in parse_results for candidate in result.candidates]

    events: list[ReviewEvent] = []
    for spec in specs:
        matched = [
            candidate
            for candidate in candidates
            if candidate.predicate == spec["target_predicate"]
            and candidate.scope.asset_id == spec["confirmed_asset_id"]
        ]
        if not matched:
            raise ValueError(f"人工确认声明找不到目标候选：{spec}")
        for candidate in matched:
            events.append(
                ReviewEvent(
                    id=allocator.allocate(prefix="REV", project_id=project_id),
                    project_id=project_id,
                    previous_snapshot_id=meta.get("previous_snapshot_id", "NONE"),
                    action=ReviewAction(spec["action"]),
                    target_candidate_id=candidate.id,
                    confirmed_asset_id=spec["confirmed_asset_id"],
                    actor_id=spec["actor_id"],
                    reason=spec["reason"],
                    occurred_at=evaluation_time,
                )
            )
    return events


def _bundle_materials(
    mode: str, case_dir: Path, snapshot: EvidenceSnapshot
) -> dict[str, Path]:
    """真实模式下把材料原件一并纳入证据包；替身模式没有原件。"""
    if mode != MODE_REAL:
        return {}
    return {
        f"materials/{artifact.original_name}": case_dir / "materials" / artifact.storage_key
        for artifact in snapshot.artifacts
    }


def _classify(path: Path) -> tuple[ArtifactKind, str]:
    suffix = path.suffix.lower()
    if suffix in _CONFIG_SUFFIXES:
        return ArtifactKind.CONFIG, "NGINX_CONF"
    if suffix in _PEM_SUFFIXES:
        return ArtifactKind.CERTIFICATE, "X509_PEM"
    if suffix in _DER_SUFFIXES:
        return ArtifactKind.CERTIFICATE, "X509_DER"
    raise ValueError(f"无法识别的材料类型：{path.name}")


def _basename(value: str) -> str:
    return PurePosixPath(PureWindowsPath(value).name).name


def _limitations(mode: str, case_name: str) -> list[str]:
    if mode == MODE_REAL:
        return [
            "材料为合成演示材料，用于验证解析与判定链路，不代表真实被测系统。",
            "规则包内容未与快照里的 rule_version 逐字节比对：流程现算规则包 sm3，"
            "核验端重建规则包做语义重放，但尚未把清单记录的 sm3 与实际规则文件对账。",
            "报告只呈现输入快照与判定结果，不重新计算也不改写结论。",
        ]
    return [
        f"快照来自契约样例 {CASE_FILES[case_name]}（测试替身），不是成员一真实解析的输出。",
        "契约样例是历史规则版本 demo-0.2.0，只跑它声明的那条判定规则。",
        "规则包内容未与快照里的 rule_version 逐字节比对：流程现算规则包 sm3，"
        "核验端重建规则包做语义重放，但尚未把清单记录的 sm3 与实际规则文件对账。",
        "报告只呈现输入快照与判定结果，不重新计算也不改写结论。",
    ]


# --------------------------------------------------------------------------- 收尾


def _finalize(
    case_name: str,
    mode: str,
    clock: Clock,
    started_at: datetime,
    stages: list[StageRecord],
    plan: tuple[tuple[str, str, str], ...],
    snapshot: EvidenceSnapshot | None,
    decisions: list[Decision],
    report_result: ReportBuildResult | None,
    bundle_path: Path | None,
    verification: VerifyResult | None,
    failure_reason: str | None,
    case_dir: Path,
) -> RunRecord:
    _fill_skipped(stages, plan)
    record = RunRecord(
        case_name=case_name,
        mode=mode,
        sample_file=CASE_FILES.get(case_name, ""),
        head_commit=_head_commit(PROJECT_ROOT),
        interface_version=INTERFACE_VERSION,
        rule_id=RULE_ID,
        rule_version=snapshot.rule_version if snapshot is not None else None,
        evaluation_time=_iso(snapshot.evaluation_time) if snapshot is not None else None,
        snapshot_id=snapshot.id if snapshot is not None else None,
        started_at=_iso(started_at),
        finished_at=_iso(clock()),
        overall_status=FAILED if failure_reason else SUCCEEDED,
        conclusion_state=_conclusion_state(decisions),
        stages=tuple(stages),
        decision_ids=tuple(decision.id for decision in decisions),
        report_path=str(report_result.path) if report_result is not None else None,
        bundle_path=str(bundle_path) if bundle_path is not None else None,
        verification=_verification_dict(verification),
        failure_reason=failure_reason,
    )
    case_dir.mkdir(parents=True, exist_ok=True)
    record_path = case_dir / "run-record.json"
    record_path.write_text(
        json.dumps(record.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return dataclasses.replace(record, record_path=str(record_path))


def _count_severity(findings: list[RiskFinding], severity: RiskSeverity) -> int:
    return sum(1 for finding in findings if finding.severity is severity)


def _fill_skipped(
    stages: list[StageRecord], plan: tuple[tuple[str, str, str], ...]
) -> None:
    """上游失败后，未执行的阶段显式记为 SKIPPED，而不是悄悄消失。"""
    recorded = {stage.stage for stage in stages}
    for stage, implementation, owner in plan:
        if stage not in recorded:
            stages.append(
                StageRecord(stage, implementation, owner, SKIPPED, "上游阶段未成功，未执行")
            )


def _conclusion_state(decisions: list[Decision]) -> str | None:
    if not decisions:
        return None
    states = {str(decision.workflow_status) for decision in decisions}
    if "CONFLICT" in states:
        return "CONFLICT"
    if "PENDING_EVIDENCE" in states:
        return "PENDING_EVIDENCE"
    return "EVALUATED"


def _verification_dict(verification: VerifyResult | None) -> dict | None:
    if verification is None:
        return None
    return {
        "bundle_id": str(verification.bundle_id),
        "integrity_status": str(verification.integrity_status),
        "replay_status": str(verification.replay_status),
        "errors": [
            {
                "code": error.code,
                "stage": error.stage,
                "artifact_id": error.artifact_id,
                "message": error.message,
                "retryable": error.retryable,
            }
            for error in verification.errors
        ],
        "display_note": (
            "完整性 PASS 只表示包内文件与其清单记录的 SM3 一致；"
            "清单本身没有签名、身份认证或防回滚保护；"
            "重放 PASS 表示用规则包重算判定后与记录一致。"
        ),
    }


def _fixed_clock(now: datetime) -> Clock:
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("--now 必须是带 UTC 时区的时刻，例如 2026-09-28T08:00:00Z")

    def clock() -> datetime:
        return now

    return clock


def _parse_utc(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"时间必须带 UTC 时区：{text!r}")
    return parsed.astimezone(timezone.utc)


def _head_commit(root: Path) -> str:
    """记录软件提交号；取不到时如实写 UNKNOWN，不编造版本。"""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"
    if completed.returncode != 0:
        return "UNKNOWN"
    return completed.stdout.strip() or "UNKNOWN"


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def run_all(
    *,
    output_root: Path | None = None,
    examples_dir: Path | None = None,
    materials_dir: Path | None = None,
    now: datetime | None = None,
    mode: str = MODE_FIXTURE,
) -> list[RunRecord]:
    """按固定顺序跑该模式下的全部样例，各自使用全新的 IdAllocator，保证结果可复现。"""
    case_names = REAL_CASES if mode == MODE_REAL else CONTRACT_CASES
    return [
        run_case(
            case_name,
            output_root=output_root,
            examples_dir=examples_dir,
            materials_dir=materials_dir,
            now=now,
            id_allocator=IdAllocator(),
            mode=mode,
        )
        for case_name in case_names
    ]


def utc_from_iso(text: str) -> datetime:
    """解析命令行传入的 ``--now``，要求带 UTC 时区。"""
    return _parse_utc(text)


def describe_clock() -> Callable[[], datetime]:
    """返回默认时钟，供外部显式使用。"""
    return utc_now
