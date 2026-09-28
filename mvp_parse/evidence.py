"""成员一的 EvidenceBuilder：核对原件、来源、对象、链路、时间与人工确认后产出准入事实。

成员一交付的 `member1_evidence_builder.py` 是 0 字节空文件，本模块按交付清单补齐三条
最小路径：

1. 同一项目、对象和核查时间下整理候选事实（`admitted_facts` 只引用快照内的候选，
   且逐字段与候选一致，不借「准入」改写值或范围）；
2. 无法确认绑定时产生 `MISSING_BINDING` 缺口，**不**生成「未使用该证书」的否定事实；
3. 单份文件解析失败时保留其他材料的结果，并把错误留在 `errors` 里（解析失败的材料
   不产生候选，自然也不会进入准入）。

关于「绑定候选」的由来：契约里 `ParseRequest` 只带一份材料，解析器无法跨材料关联证书，
因此由本模块在整理阶段把「配置里的 `ssl_certificate` 路径」与「证书材料」关联，派生出
`service_uses_certificate` 候选（来源锚点仍指向配置行）。该候选**只有**在人工确认事件
存在时才被准入，符合「候选 ≠ 结论」的分工。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import (
    AdmittedFact,
    Artifact,
    ArtifactKind,
    CandidateFact,
    EvidenceLevel,
    EvidenceSnapshot,
    Gap,
    ParseResult,
    ReviewAction,
    ReviewEvent,
    Scope,
)

SNAPSHOT_ID_PREFIX = "FS"
GAP_ID_PREFIX = "GAP"
CANDIDATE_PREFIX = "CAND"
ADMITTED_FACT_PREFIX = "FACT"

CONFIGURED_CERTIFICATE_PATH = "configured_certificate_path"
SERVICE_USES_CERTIFICATE = "service_uses_certificate"

CERTIFICATE_KEY_USAGE = "certificate_key_usage"
CERTIFICATE_EXTENDED_KEY_USAGE = "certificate_extended_key_usage"
CERTIFICATE_PUBLIC_KEY_ALGORITHM = "certificate_public_key_algorithm"
CERTIFICATE_PUBLIC_KEY_SIZE = "certificate_public_key_size"
CERTIFICATE_PUBLIC_KEY_CURVE = "certificate_public_key_curve"

TARGET_CONDITION_BINDING = "binding"
TARGET_CONDITION_CERTIFICATE_EVIDENCE = "certificate_evidence"
REASON_CODE_MISSING_BINDING = "MISSING_BINDING"
REASON_CODE_MISSING_CERTIFICATE_EVIDENCE = "MISSING_CERTIFICATE_EVIDENCE"

#: 与解析器一致的算法名（``mvp_parse.x509_certificate._public_key_algorithm``）。
RSA_KEY_ALGORITHM = "RSAPublicKey"
EC_KEY_ALGORITHM = "EllipticCurvePublicKey"


class EvidenceBuildError(RuntimeError):
    """证据无法整理成符合契约的快照时抛出。"""


class EvidenceBuilder:
    """实现 ``mvp_contracts.interfaces.EvidenceBuilder``。"""

    def __init__(
        self, id_allocator: IdAllocator, *, parser_version: str = "evidence-0.2.0"
    ) -> None:
        self._id_allocator = id_allocator
        self._parser_version = parser_version

    def build_snapshot(
        self,
        *,
        project_id: str,
        evaluation_time: datetime,
        rule_version: str,
        artifacts: list[Artifact],
        parse_results: list[ParseResult],
        review_events: list[ReviewEvent],
    ) -> EvidenceSnapshot:
        artifacts = list(artifacts)
        parse_results = list(parse_results)
        review_events = list(review_events)

        candidates = [c for result in parse_results for c in result.candidates]
        errors = [error for result in parse_results for error in result.errors]

        known_candidate_ids = {candidate.id for candidate in candidates}
        for event in review_events:
            if (
                event.target_candidate_id is not None
                and event.target_candidate_id not in known_candidate_ids
            ):
                raise EvidenceBuildError(
                    f"人工事件 {event.id} 引用了不在本次解析结果中的候选 "
                    f"{event.target_candidate_id}"
                )

        # 绑定候选由 derive_binding_candidates() 在人工事件构造之前追加进 parse_results：
        # 契约要求 AdmittedFact.candidate_id == ReviewEvent.target_candidate_id，
        # 事件的 target 必须指向绑定候选本身，不能指向配置路径候选。
        admitted = self._admit(project_id, candidates, review_events)
        gaps = self._gaps(project_id, admitted)

        return EvidenceSnapshot(
            id=self._id_allocator.allocate(
                prefix=SNAPSHOT_ID_PREFIX, project_id=project_id
            ),
            project_id=project_id,
            evaluation_time=evaluation_time,
            rule_version=rule_version,
            artifacts=artifacts,
            candidates=candidates,
            admitted_facts=admitted,
            gaps=gaps,
            review_events=review_events,
            errors=errors,
        )

    def _admit(
        self,
        project_id: str,
        candidates: list[CandidateFact],
        review_events: list[ReviewEvent],
    ) -> list[AdmittedFact]:
        confirmations = {
            event.target_candidate_id: event
            for event in review_events
            if event.action is ReviewAction.CONFIRM_BINDING
            and event.target_candidate_id is not None
        }

        admitted: list[AdmittedFact] = []
        for candidate in candidates:
            if candidate.value is None:
                continue  # 准入事实必须有确定的值，未知不写进事实

            if candidate.predicate == SERVICE_USES_CERTIFICATE:
                event = confirmations.get(candidate.id)
                if event is None or event.confirmed_asset_id != candidate.scope.asset_id:
                    continue
                admission_reason = (
                    f"人工确认事件 {event.id} 确认对象 {event.confirmed_asset_id} "
                    "使用该证书"
                )
                review_event_id: str | None = event.id
            else:
                if candidate.scope.asset_id is None:
                    continue  # 对象不明确的事实不进入正式判断
                admission_reason = "候选事实的对象、范围与原件来源均可追溯"
                review_event_id = None

            admitted.append(
                AdmittedFact(
                    id=self._id_allocator.allocate(
                        prefix=ADMITTED_FACT_PREFIX, project_id=project_id
                    ),
                    candidate_id=candidate.id,
                    artifact_id=candidate.artifact_id,
                    anchor=candidate.anchor,
                    predicate=candidate.predicate,
                    value=candidate.value,
                    scope=candidate.scope,
                    evidence_level=candidate.evidence_level,
                    admission_reason=admission_reason,
                    review_event_id=review_event_id,
                )
            )
        return admitted

    def _gaps(self, project_id: str, admitted: list[AdmittedFact]) -> list[Gap]:
        """对「有条件判断、但缺条件所需证据」的地方产生缺口。

        两类缺口：

        * ``binding``——对象有可用证据，却没有已确认绑定；
        * ``certificate_purpose``——对象已确认使用某证书，但该证书缺少用途扩展
          事实，无法判断它是否被限定用于服务端身份鉴别。

        证书**确实没有**某个扩展时，解析器不会产出该字段的候选；此时本方法不臆断
        「用途不合规」，而是如实记录缺口，让判定停在待补证、由人工复核确认。
        """
        object_scopes: dict[str, Scope] = {}
        bound_certificate: dict[str, str] = {}
        facts_by_artifact: dict[str, dict[str, object]] = {}
        for fact in admitted:
            asset_id = fact.scope.asset_id
            if asset_id is None:
                continue
            object_scopes.setdefault(asset_id, fact.scope)
            facts_by_artifact.setdefault(fact.artifact_id, {})[fact.predicate] = fact.value
            if fact.predicate == SERVICE_USES_CERTIFICATE and isinstance(fact.value, str):
                bound_certificate.setdefault(asset_id, fact.value)

        gaps: list[Gap] = []
        for asset_id, scope in object_scopes.items():
            certificate_id = bound_certificate.get(asset_id)
            if certificate_id is None:
                gaps.append(
                    Gap(
                        id=self._id_allocator.allocate(
                            prefix=GAP_ID_PREFIX, project_id=project_id
                        ),
                        target_condition=TARGET_CONDITION_BINDING,
                        reason_code=REASON_CODE_MISSING_BINDING,
                        scope=scope,
                        description=f"缺少证明 {asset_id} 当前使用的证书的绑定记录",
                    )
                )
                continue

            missing = _missing_certificate_evidence(
                facts_by_artifact.get(certificate_id, {})
            )
            if missing:
                gaps.append(
                    Gap(
                        id=self._id_allocator.allocate(
                            prefix=GAP_ID_PREFIX, project_id=project_id
                        ),
                        target_condition=TARGET_CONDITION_CERTIFICATE_EVIDENCE,
                        reason_code=REASON_CODE_MISSING_CERTIFICATE_EVIDENCE,
                        scope=scope,
                        description=(
                            f"{asset_id} 绑定的证书缺少判定所需的{'、'.join(missing)}，"
                            "无法确认其用途与密钥强度是否满足要求"
                        ),
                    )
                )
        return gaps


def _missing_certificate_evidence(facts: dict[str, object]) -> list[str]:
    """列出判定规则需要、但这份证书确实没有提供的字段。

    证书**确实没有**某个扩展时，解析器不产出该字段的候选；这里如实记录缺口，而
    不是臆断「用途不合规」或「密钥强度不足」。判定侧据此停在待补证，由人工复核。
    """
    missing: list[str] = []
    if not {CERTIFICATE_KEY_USAGE, CERTIFICATE_EXTENDED_KEY_USAGE} & facts.keys():
        missing.append("keyUsage/ExtendedKeyUsage 扩展")

    algorithm = facts.get(CERTIFICATE_PUBLIC_KEY_ALGORITHM)
    if algorithm is None:
        missing.append("公钥算法")
    elif algorithm == RSA_KEY_ALGORITHM:
        if CERTIFICATE_PUBLIC_KEY_SIZE not in facts:
            missing.append("RSA 密钥长度")
    elif algorithm == EC_KEY_ALGORITHM and CERTIFICATE_PUBLIC_KEY_CURVE not in facts:
        missing.append("椭圆曲线名称")
    return missing


def _certificate_assets(candidates: list[CandidateFact]) -> dict[str, str]:
    """证书材料 → 已明确的对象，取自该证书候选的 ``scope.asset_id``。"""
    mapping: dict[str, str] = {}
    for candidate in candidates:
        if candidate.evidence_level is not EvidenceLevel.CERTIFICATE:
            continue
        asset_id = candidate.scope.asset_id
        if asset_id is None:
            continue
        mapping.setdefault(candidate.artifact_id, asset_id)
    return mapping


def _basename(value: str) -> str:
    """取路径最后一段，同时兼容 Windows 与 POSIX 分隔符。"""
    return PurePosixPath(PureWindowsPath(value).name).name


def derive_binding_candidates(
    *,
    project_id: str,
    artifacts: list[Artifact],
    parse_results: list[ParseResult],
    id_allocator: IdAllocator,
    parser_version: str = "evidence-0.2.0",
) -> list[ParseResult]:
    """把配置里的证书路径与证书材料关联成绑定候选，追加进配置材料的解析结果。

    必须在构造人工确认事件**之前**调用：契约要求
    ``AdmittedFact.candidate_id == ReviewEvent.target_candidate_id``，所以事件的
    ``target_candidate_id`` 只能指向已经存在的绑定候选，不能指向配置路径候选。

    只在「证书材料本身已有明确对象」且「该对象与配置对象一致」时才派生；否则保持
    未知，交由缺口表达，不猜绑定。
    """
    certificate_by_name = {
        artifact.original_name: artifact
        for artifact in artifacts
        if artifact.kind is ArtifactKind.CERTIFICATE
    }
    candidates = [
        candidate for result in parse_results for candidate in result.candidates
    ]
    certificate_assets = _certificate_assets(candidates)

    additions: dict[str, list[CandidateFact]] = {}
    for candidate in candidates:
        if candidate.predicate != CONFIGURED_CERTIFICATE_PATH:
            continue
        if not isinstance(candidate.value, str) or candidate.scope.asset_id is None:
            continue
        certificate = certificate_by_name.get(_basename(candidate.value))
        if certificate is None:
            continue
        if certificate_assets.get(certificate.id) != candidate.scope.asset_id:
            continue
        additions.setdefault(candidate.artifact_id, []).append(
            CandidateFact(
                id=id_allocator.allocate(
                    prefix=CANDIDATE_PREFIX, project_id=project_id
                ),
                artifact_id=candidate.artifact_id,
                anchor=candidate.anchor,
                predicate=SERVICE_USES_CERTIFICATE,
                value=certificate.id,
                scope=candidate.scope,
                evidence_level=EvidenceLevel.CONFIGURED,
                parser_version=parser_version,
            )
        )

    if not additions:
        return list(parse_results)
    return [
        result.model_copy(
            update={
                "candidates": result.candidates
                + additions.get(result.artifact_id, [])
            }
        )
        for result in parse_results
    ]
