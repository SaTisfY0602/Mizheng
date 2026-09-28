"""成员二判定模块：固定规则的原子条件求值与判定组装。

对外提供：

* 条件求值器——``evaluate_demo_bind_time``（绑定 + 证书有效期）、
  ``evaluate_certificate_key_strength``、``evaluate_certificate_purpose``；
* ``DecisionEngine``——按规则包声明的规则集合把这些条件组装成共享 ``Decision``；
* ``BundleVerifier``——独立核验本地证据包的文件完整性与规则重放。

判定侧的阈值来自版本化规则包 ``mvp_rules``，与风险侧同源。
"""

from .engine import (
    RULE_REGISTRY,
    SUPPORTED_RULE_IDS,
    DecisionEngine,
    DecisionEngineError,
    RuleDefinition,
    RulePackError,
    default_rule_ids,
)
from .rules import (
    AmbiguousScopeError,
    ConflictingBindingError,
    EvaluatedConditions,
    RuleEvaluationError,
    UnparseableTimeError,
    evaluate_certificate_key_strength,
    evaluate_certificate_purpose,
    evaluate_demo_bind_time,
)
from .verifier import BundleVerifier

__all__ = [
    "RULE_REGISTRY",
    "SUPPORTED_RULE_IDS",
    "AmbiguousScopeError",
    "BundleVerifier",
    "ConflictingBindingError",
    "DecisionEngine",
    "DecisionEngineError",
    "EvaluatedConditions",
    "RuleDefinition",
    "RuleEvaluationError",
    "RulePackError",
    "UnparseableTimeError",
    "default_rule_ids",
    "evaluate_certificate_key_strength",
    "evaluate_certificate_purpose",
    "evaluate_demo_bind_time",
]
