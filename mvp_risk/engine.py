"""风险规则引擎：按固定顺序运行风险规则，输出可解释、可溯源的风险清单。"""

from __future__ import annotations

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import EvidenceSnapshot
from mvp_rules import default_rule_set

from .findings import RiskFinding, severity_order
from .rules import (
    RiskDraft,
    binding_risks,
    certificate_algorithm_risks,
    certificate_name_risks,
    certificate_purpose_risks,
    certificate_time_risks,
    certificate_trust_risks,
    certificate_validity_risks,
    transport_risks,
)

RISK_ID_PREFIX = "RISK"
EXPIRING_RULE_ID = "RISK-CERT-EXPIRING"


class RiskEngine:
    """组装风险清单；与 ``DecisionEngine`` 平级，但回答的是「有什么风险」。"""

    def __init__(
        self,
        id_allocator: IdAllocator,
        *,
        expiring_within_days: int | None = None,
    ) -> None:
        self._id_allocator = id_allocator
        # 缺省天数来自规则包，而不是写死在代码里；显式传入只用于测试边界场景。
        self._expiring_within_days = (
            expiring_within_days
            if expiring_within_days is not None
            else default_rule_set().int_param(EXPIRING_RULE_ID, "expiring_days")
        )

    def evaluate(self, snapshot: EvidenceSnapshot) -> list[RiskFinding]:
        drafts: list[RiskDraft] = []
        drafts.extend(
            certificate_time_risks(snapshot, expiring_days=self._expiring_within_days)
        )
        drafts.extend(certificate_validity_risks(snapshot))
        drafts.extend(certificate_algorithm_risks(snapshot))
        drafts.extend(certificate_trust_risks(snapshot))
        drafts.extend(certificate_purpose_risks(snapshot))
        drafts.extend(certificate_name_risks(snapshot))
        drafts.extend(transport_risks(snapshot))
        drafts.extend(binding_risks(snapshot))

        findings = [
            RiskFinding(
                id=self._id_allocator.allocate(
                    prefix=RISK_ID_PREFIX, project_id=snapshot.project_id
                ),
                rule_id=draft.rule_id,
                severity=draft.severity,
                object_id=draft.object_id,
                title=draft.title,
                description=draft.description,
                evidence_fact_ids=draft.evidence_fact_ids,
                remediation=draft.remediation,
            )
            for draft in drafts
        ]
        # 先按等级、再按对象与规则 ID 排序，保证相同输入得到相同顺序
        findings.sort(
            key=lambda finding: (
                severity_order(finding.severity),
                finding.object_id or "",
                finding.rule_id,
            )
        )
        return findings
