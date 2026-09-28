"""风险项对象：风险规则引擎的输出，供报告渲染风险清单与整改建议。

风险项刻意**不放进共享契约**（``mvp_contracts.models``）。共享契约描述的是
「证据 → 判定」的交接对象，而风险清单是报告层的产物；等下一阶段确实需要跨模块
交接风险项时，再按协作规范 §6.1 连同共享类、样例、测试一起升级契约版本。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class RiskSeverity(StrEnum):
    """风险等级；顺序即报告排序依据。"""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_SEVERITY_ORDER = {RiskSeverity.HIGH: 0, RiskSeverity.MEDIUM: 1, RiskSeverity.LOW: 2}


def severity_order(severity: RiskSeverity) -> int:
    return _SEVERITY_ORDER[severity]


@dataclass(frozen=True)
class RiskFinding:
    """一条可解释、可溯源的风险项。"""

    id: str
    rule_id: str
    severity: RiskSeverity
    object_id: str | None
    title: str
    description: str
    evidence_fact_ids: tuple[str, ...]
    remediation: str

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["severity"] = str(self.severity)
        payload["evidence_fact_ids"] = list(self.evidence_fact_ids)
        return payload
