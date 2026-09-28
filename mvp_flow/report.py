"""成员三拥有的报告生成：把快照与判定整理成可交付的测评报告初稿。

边界（协作规范 §2）：报告只呈现**输入快照**和**判定结果**，不重新计算规则、
不改写结论、不把未知写成符合。待补证的判定必须在报告里保持待补证，并给出补证
请求；核验结果不写入报告正文（核验发生在导出之后，写入会改变报告摘要）。
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import (
    Decision,
    EvidenceSnapshot,
    Gap,
    ReportArtifact,
    WorkflowStatus,
)

from .digest import sm3_of_bytes
from mvp_risk import RiskFinding, RiskSeverity

DEFAULT_REPORT_FILE_NAME = "assessment-draft.json"
REPORT_ID_PREFIX = "RPT"

Clock = Callable[[], datetime]

# 「缺口原因码 → 补证请求文案」对应表（第六章的最小版本）。
_REASON_TEXTS = {
    "MISSING_BINDING": "请补充目标对象正在使用该证书的绑定记录（配置、握手抓包或人工确认事件）。",
    "MISSING_NOT_AFTER": "请补充该证书的有效期材料（证书原件或证书链）。",
}
_DEFAULT_REASON_TEXT = "请补充该条件对应的材料，并在补齐后重新判定受影响对象。"


def utc_now() -> datetime:
    """默认时钟：当前 UTC 时刻。"""
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ReportBuildResult:
    """报告文件、其契约对象与已序列化的内容。"""

    report: ReportArtifact
    path: Path
    payload: dict


class ReportBuilder:
    """生成 ``assessment-draft.json`` 报告初稿。"""

    def __init__(self, id_allocator: IdAllocator, *, clock: Clock = utc_now) -> None:
        self._id_allocator = id_allocator
        self._clock = clock

    def build(
        self,
        snapshot: EvidenceSnapshot,
        decisions: Sequence[Decision],
        output_dir: Path,
        *,
        file_name: str = DEFAULT_REPORT_FILE_NAME,
        limitations: Sequence[str] = (),
        risk_findings: Sequence[RiskFinding] = (),
    ) -> ReportBuildResult:
        decision_list = list(decisions)
        generated_at = self._clock()
        payload = _build_payload(
            snapshot,
            decision_list,
            generated_at,
            list(limitations),
            list(risk_findings),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        path = output_dir / file_name
        path.write_bytes(encoded)

        report = ReportArtifact(
            schema_version=snapshot.schema_version,
            id=self._id_allocator.allocate(
                prefix=REPORT_ID_PREFIX, project_id=snapshot.project_id
            ),
            snapshot_id=snapshot.id,
            decision_ids=[decision.id for decision in decision_list],
            unresolved_decision_ids=[
                decision.id
                for decision in decision_list
                if decision.workflow_status is not WorkflowStatus.EVALUATED
            ],
            file_name=file_name,
            sm3=sm3_of_bytes(encoded),
            created_at=generated_at,
        )
        return ReportBuildResult(report=report, path=path, payload=payload)


def _build_payload(
    snapshot: EvidenceSnapshot,
    decisions: list[Decision],
    generated_at: datetime,
    limitations: list[str],
    risk_findings: list[RiskFinding],
) -> dict:
    gaps_by_id = {gap.id: gap for gap in snapshot.gaps}
    evaluated = [
        d for d in decisions if d.workflow_status is WorkflowStatus.EVALUATED
    ]
    pending = [
        d for d in decisions if d.workflow_status is WorkflowStatus.PENDING_EVIDENCE
    ]
    conflicted = [d for d in decisions if d.workflow_status is WorkflowStatus.CONFLICT]

    if conflicted:
        overall = WorkflowStatus.CONFLICT
        statement = "本次运行存在证据冲突，不给出唯一结论；请先解决冲突后再判断。"
    elif pending:
        overall = WorkflowStatus.PENDING_EVIDENCE
        statement = (
            "本次运行存在待补证条件，报告只列出可能结论，不构成最终符合性判定。"
        )
    else:
        overall = WorkflowStatus.EVALUATED
        statement = "本次运行的判定均已形成唯一建议；结论只对本快照列出的材料成立。"

    return {
        "schema_version": snapshot.schema_version,
        "report_kind": "assessment-draft",
        "generated_at": _iso(generated_at),
        "project_id": snapshot.project_id,
        "snapshot_id": snapshot.id,
        "rule_version": snapshot.rule_version,
        "evaluation_time": _iso(snapshot.evaluation_time),
        "conclusion": {
            "state": str(overall),
            "statement": statement,
            # 结论按**对象**归集：一个对象可能有多条判定（每条对应一个指标项），
            # 但它在结论里只该出现一次。
            "evaluated_objects": _object_ids(evaluated),
            "pending_objects": _object_ids(pending),
            "conflicted_objects": _object_ids(conflicted),
        },
        "summary": {
            "decision_count": len(decisions),
            "evaluated": len(evaluated),
            "pending_evidence": len(pending),
            "conflict": len(conflicted),
        },
        "decisions": [_decision_view(d, gaps_by_id) for d in decisions],
        "gaps": [_gap_view(gap) for gap in snapshot.gaps],
        "follow_up_requests": _follow_up_requests(decisions, gaps_by_id),
        "trust_boundary": {
            "integrity": (
                "证据包完整性由独立入口核对，只证明包内文件与其清单记录的 SM3 一致。"
            ),
            "manifest_provenance": (
                "清单本身没有签名、身份认证或防回滚保护；清单来源的可信性不由本报告保证。"
            ),
            "rule_replay": (
                "规则重放由核验器用规则包与包内快照重算判定，并与记录做语义比对；"
                "比对忽略重新分配的判定 ID，只对对象、条件状态、可能结论、建议标签、"
                "工作流状态与事实/缺口引用。"
            ),
        },
        "risk_summary": {
            "total": len(risk_findings),
            "high": _count_severity(risk_findings, RiskSeverity.HIGH),
            "medium": _count_severity(risk_findings, RiskSeverity.MEDIUM),
            "low": _count_severity(risk_findings, RiskSeverity.LOW),
        },
        "risks": [finding.to_dict() for finding in risk_findings],
        "limitations": limitations,
    }


def _count_severity(findings: list[RiskFinding], severity: RiskSeverity) -> int:
    return sum(1 for finding in findings if finding.severity is severity)


def _object_ids(decisions: list[Decision]) -> list[str]:
    """按判定顺序去重地取出对象 ID——同一对象的多条判定只列一次。"""
    seen: dict[str, None] = {}
    for decision in decisions:
        seen.setdefault(decision.object_id, None)
    return list(seen)


def _decision_view(decision: Decision, gaps_by_id: dict[str, Gap]) -> dict:
    return {
        "decision_id": decision.id,
        "object_id": decision.object_id,
        "rule_id": decision.rule_id,
        "rule_version": decision.rule_version,
        "condition_states": {
            name: str(state) for name, state in decision.condition_states.items()
        },
        "possible_labels": [str(label) for label in decision.possible_labels],
        "proposed_label": (
            str(decision.proposed_label)
            if decision.proposed_label is not None
            else None
        ),
        "workflow_status": str(decision.workflow_status),
        "support_fact_ids": list(decision.support_fact_ids),
        "gaps": [
            _gap_view(gaps_by_id[gap_id], decision.object_id)
            for gap_id in decision.gap_ids
            if gap_id in gaps_by_id
        ],
    }


def _gap_view(gap: Gap, object_id: str | None = None) -> dict:
    return {
        "gap_id": gap.id,
        "object_id": object_id if object_id is not None else gap.scope.asset_id,
        "target_condition": gap.target_condition,
        "reason_code": gap.reason_code,
        "description": gap.description,
    }


def _follow_up_requests(
    decisions: list[Decision], gaps_by_id: dict[str, Gap]
) -> list[dict]:
    """把未决判定的缺口展开成「缺口—动作」补证请求。

    已完成（EVALUATED）的判定不产生补证请求；同一缺口被多个判定引用时只请求一次。
    """
    requests: list[dict] = []
    seen: set[str] = set()
    for decision in decisions:
        if decision.workflow_status is WorkflowStatus.EVALUATED:
            continue
        for gap_id in decision.gap_ids:
            gap = gaps_by_id.get(gap_id)
            if gap is None or gap.id in seen:
                continue
            seen.add(gap.id)
            requests.append(
                {
                    "gap_id": gap.id,
                    "object_id": decision.object_id,
                    "target_condition": gap.target_condition,
                    "reason_code": gap.reason_code,
                    "priority": "high" if gap.target_condition == "binding" else "medium",
                    "action": "REQUEST_EVIDENCE",
                    "request_text": _REASON_TEXTS.get(
                        gap.reason_code, _DEFAULT_REASON_TEXT
                    ),
                }
            )
    return requests


def _iso(moment: datetime) -> str:
    """契约 JSON 使用 ``Z`` 结尾的 UTC 时刻。"""
    return moment.isoformat().replace("+00:00", "Z")
