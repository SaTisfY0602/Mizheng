"""风险识别模块：把已准入证据映射成风险清单与整改建议。

对应题目功能要求 2（密码风险自动识别）与要求 4（风险项清单及整改建议）。
风险项不进入共享契约，理由见 ``findings.py`` 的模块说明。

弱算法/弱协议名单与阈值**不在本包内硬编码**，而是来自版本化规则包
``mvp_rules``；``RISK_RULE_IDS`` 便于对账「规则包声明了什么」与「本包实现了什么」。
"""

from .engine import EXPIRING_RULE_ID, RISK_ID_PREFIX, RiskEngine
from .findings import RiskFinding, RiskSeverity, severity_order
from .rules import RiskDraft

__all__ = [
    "EXPIRING_RULE_ID",
    "RISK_ID_PREFIX",
    "RiskDraft",
    "RiskEngine",
    "RiskFinding",
    "RiskSeverity",
    "severity_order",
]

# 本包实现的全部风险规则 ID。与规则包 ``rules_risk.json`` 的对账测试会断言两者一致，
# 防止出现「规则包声明了但代码没实现」或反过来的静默漂移。
RISK_RULE_IDS: tuple[str, ...] = (
    "RISK-TLS-WEAK-PROTOCOL",
    "RISK-TLS-WEAK-CIPHER",
    "RISK-CERT-EXPIRED",
    "RISK-CERT-EXPIRING",
    "RISK-CERT-WEAK-SIGNATURE",
    "RISK-CERT-SIGNATURE-UNKNOWN",
    "RISK-CERT-WEAK-KEY",
    "RISK-CERT-TIME-MISSING",
    "RISK-CERT-TIME-UNPARSABLE",
    "RISK-CERT-NOT-YET-VALID",
    "RISK-CERT-SELF-SIGNED",
    "RISK-CERT-UNTRUSTED-ISSUER",
    "RISK-CERT-PURPOSE-MISSING",
    "RISK-CERT-EKU-NOT-SERVER-AUTH",
    "RISK-CERT-SAN-MISMATCH",
    "RISK-BINDING-UNKNOWN",
)
