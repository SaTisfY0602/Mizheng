"""Validated transport objects. Persistence models must live elsewhere."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
FactValue = str | int | bool | list[str]
SchemaVersion = Literal["0.2.0-mvp"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="after")
    @classmethod
    def require_utc(cls, value: object) -> object:
        if isinstance(value, datetime) and (
            value.tzinfo is None or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("时间必须带 UTC 时区")
        return value


class ArtifactKind(StrEnum):
    CONFIG = "CONFIG"
    CERTIFICATE = "CERTIFICATE"


class AnchorKind(StrEnum):
    CONFIG_LINE = "CONFIG_LINE"
    CERT_FIELD = "CERT_FIELD"


class EvidenceLevel(StrEnum):
    CONFIGURED = "CONFIGURED"
    CERTIFICATE = "CERTIFICATE"
    MANUAL = "MANUAL"


class ConditionState(StrEnum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"


class Outcome(StrEnum):
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class WorkflowStatus(StrEnum):
    EVALUATED = "EVALUATED"
    PENDING_EVIDENCE = "PENDING_EVIDENCE"
    CONFLICT = "CONFLICT"


class ParseStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ReviewAction(StrEnum):
    CONFIRM_BINDING = "CONFIRM_BINDING"
    REQUEST_EVIDENCE = "REQUEST_EVIDENCE"
    REVOKE_BINDING = "REVOKE_BINDING"


class CheckStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


class Scope(ContractModel):
    project_id: str
    environment: str
    asset_id: str | None
    link_id: str | None
    as_of: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None

    @model_validator(mode="after")
    def valid_interval(self) -> Scope:
        if self.valid_from and self.valid_to and self.valid_from > self.valid_to:
            raise ValueError("适用时间起点不能晚于终点")
        return self


class Artifact(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    project_id: str
    kind: ArtifactKind
    format: Literal["NGINX_CONF", "X509_PEM", "X509_DER"]
    original_name: str
    sm3: Digest
    byte_size: int = Field(ge=0)
    storage_key: str
    imported_at: datetime

    @model_validator(mode="after")
    def matching_kind_and_format(self) -> Artifact:
        if self.kind is ArtifactKind.CONFIG and self.format != "NGINX_CONF":
            raise ValueError("配置材料格式不匹配")
        if self.kind is ArtifactKind.CERTIFICATE and self.format not in {"X509_PEM", "X509_DER"}:
            raise ValueError("证书材料格式不匹配")
        return self


class SourceAnchor(ContractModel):
    artifact_id: str
    kind: AnchorKind
    quote: str
    line_number: int | None = Field(default=None, ge=1)
    field_path: str | None = None

    @model_validator(mode="after")
    def location_matches_kind(self) -> SourceAnchor:
        if self.kind is AnchorKind.CONFIG_LINE and (self.line_number is None or self.field_path is not None):
            raise ValueError("CONFIG_LINE 必须且只填写 line_number")
        if self.kind is AnchorKind.CERT_FIELD and (not self.field_path or self.line_number is not None):
            raise ValueError("CERT_FIELD 必须且只填写 field_path")
        return self


class CandidateFact(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    artifact_id: str
    anchor: SourceAnchor
    predicate: str
    value: FactValue | None
    scope: Scope
    evidence_level: EvidenceLevel
    parser_version: str

    @model_validator(mode="after")
    def anchor_matches_artifact(self) -> CandidateFact:
        if self.anchor.artifact_id != self.artifact_id:
            raise ValueError("来源定位与事实材料不一致")
        return self


class AdmittedFact(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    candidate_id: str
    artifact_id: str
    anchor: SourceAnchor
    predicate: str
    value: FactValue
    scope: Scope
    evidence_level: EvidenceLevel
    admission_reason: str
    review_event_id: str | None = None

    @model_validator(mode="after")
    def admission_is_traceable(self) -> AdmittedFact:
        if self.anchor.artifact_id != self.artifact_id:
            raise ValueError("准入事实的定位与材料不一致")
        if self.scope.asset_id is None:
            raise ValueError("准入事实必须明确对象")
        if not self.admission_reason.strip():
            raise ValueError("准入事实必须说明依据")
        return self


class Gap(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    target_condition: str
    reason_code: str
    scope: Scope
    description: str


class ReviewEvent(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    project_id: str
    previous_snapshot_id: str
    action: ReviewAction
    target_candidate_id: str | None
    confirmed_asset_id: str | None
    actor_id: str
    reason: str
    occurred_at: datetime

    @model_validator(mode="after")
    def binding_confirmation_has_target(self) -> ReviewEvent:
        if self.action is ReviewAction.CONFIRM_BINDING and (
            not self.target_candidate_id or not self.confirmed_asset_id
        ):
            raise ValueError("确认绑定必须指出候选事实和对象")
        return self


class ErrorItem(ContractModel):
    code: str
    stage: str
    artifact_id: str | None
    message: str
    retryable: bool = False


class ParseRequest(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    artifact: Artifact
    scope: Scope
    parser_version: str

    @model_validator(mode="after")
    def project_matches(self) -> ParseRequest:
        if self.artifact.project_id != self.scope.project_id:
            raise ValueError("解析请求的项目不一致")
        return self


class ParseResult(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    artifact_id: str
    status: ParseStatus
    coverage: Literal["COMPLETE", "PARTIAL", "UNKNOWN"]
    candidates: list[CandidateFact]
    errors: list[ErrorItem]

    @model_validator(mode="after")
    def result_is_coherent(self) -> ParseResult:
        if any(f.artifact_id != self.artifact_id for f in self.candidates):
            raise ValueError("解析结果包含其他材料的事实")
        if self.status is ParseStatus.FAILED and (self.candidates or not self.errors):
            raise ValueError("解析失败须有错误且不能输出事实")
        return self


class EvidenceSnapshot(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    project_id: str
    evaluation_time: datetime
    rule_version: str
    artifacts: list[Artifact]
    candidates: list[CandidateFact]
    admitted_facts: list[AdmittedFact]
    gaps: list[Gap]
    review_events: list[ReviewEvent]
    errors: list[ErrorItem]

    @model_validator(mode="after")
    def references_are_inside_snapshot(self) -> EvidenceSnapshot:
        artifact_ids = {a.id for a in self.artifacts}
        candidates_by_id = {c.id: c for c in self.candidates}
        candidate_ids = set(candidates_by_id)
        reviews_by_id = {event.id: event for event in self.review_events}
        if len(artifact_ids) != len(self.artifacts) or len(candidate_ids) != len(self.candidates):
            raise ValueError("快照内材料或候选 ID 重复")
        if any(a.project_id != self.project_id for a in self.artifacts):
            raise ValueError("快照含其他项目材料")
        if any(c.artifact_id not in artifact_ids for c in self.candidates):
            raise ValueError("候选事实引用了快照外材料")
        if any(c.scope.project_id != self.project_id for c in self.candidates):
            raise ValueError("候选事实所属项目不匹配")
        if any(f.artifact_id not in artifact_ids or f.candidate_id not in candidate_ids for f in self.admitted_facts):
            raise ValueError("准入事实缺少对应材料或候选")
        if any(f.scope.project_id != self.project_id for f in self.admitted_facts):
            raise ValueError("准入事实所属项目不匹配")
        if any(g.scope.project_id != self.project_id for g in self.gaps):
            raise ValueError("缺口所属项目不匹配")
        if any(event.project_id != self.project_id for event in self.review_events):
            raise ValueError("人工事件所属项目不匹配")
        for fact in self.admitted_facts:
            candidate = candidates_by_id[fact.candidate_id]
            if (
                fact.artifact_id != candidate.artifact_id
                or fact.anchor != candidate.anchor
                or fact.predicate != candidate.predicate
                or fact.value != candidate.value
                or fact.scope != candidate.scope
                or fact.evidence_level != candidate.evidence_level
            ):
                raise ValueError("准入事实不能改写候选内容或范围")
            if fact.review_event_id is not None:
                review = reviews_by_id.get(fact.review_event_id)
                if review is None or review.target_candidate_id != fact.candidate_id:
                    raise ValueError("人工确认缺少对应事件")
        return self


class Decision(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    snapshot_id: str
    rule_id: str
    rule_version: str
    object_id: str
    condition_states: dict[str, ConditionState]
    possible_labels: list[Outcome]
    proposed_label: Outcome | None
    workflow_status: WorkflowStatus
    support_fact_ids: list[str]
    gap_ids: list[str]

    @model_validator(mode="after")
    def label_matches_state(self) -> Decision:
        if len(set(self.possible_labels)) != len(self.possible_labels):
            raise ValueError("可能结论不能重复")
        if self.workflow_status is WorkflowStatus.EVALUATED and (
            self.proposed_label is None or self.possible_labels != [self.proposed_label]
        ):
            raise ValueError("已形成判定时必须且只能有一个建议标签")
        if self.workflow_status is WorkflowStatus.PENDING_EVIDENCE and (
            self.proposed_label is not None
            or len(self.possible_labels) < 2
            or not self.gap_ids
        ):
            raise ValueError("待补证时必须保留歧义标签和缺口")
        if self.workflow_status is WorkflowStatus.CONFLICT and self.proposed_label is not None:
            raise ValueError("证据冲突不能给唯一建议")
        if any(s is ConditionState.CONFLICTED for s in self.condition_states.values()) and self.proposed_label is not None:
            raise ValueError("冲突条件不能给唯一建议")
        return self


class RulePack(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    version: str
    sm3: Digest
    rule_ids: list[str]


class ReportArtifact(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    snapshot_id: str
    decision_ids: list[str]
    unresolved_decision_ids: list[str]
    file_name: str
    sm3: Digest
    created_at: datetime


class BundleManifest(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    id: str
    snapshot_id: str
    rule_version: str
    decision_ids: list[str]
    report_id: str
    files: dict[str, Digest]
    created_at: datetime

    @field_validator("files")
    @classmethod
    def files_use_safe_relative_paths(cls, files: dict[str, Digest]) -> dict[str, Digest]:
        for name in files:
            parts = name.split("/")
            if (
                not name
                or name.startswith("/")
                or "\\" in name
                or ":" in name
                or any(part in {"", ".", ".."} for part in parts)
            ):
                raise ValueError("证据包文件名必须是安全的相对路径")
        return files


class VerifyResult(ContractModel):
    schema_version: SchemaVersion = "0.2.0-mvp"
    bundle_id: str
    integrity_status: CheckStatus
    replay_status: CheckStatus
    errors: list[ErrorItem]
