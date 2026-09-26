"""Member-two decision module: fixed-rule condition evaluation and assembly.

Ships the ``DEMO-BIND-TIME`` condition function, the ``DecisionEngine`` that
assembles its results into shared ``Decision`` objects, and the standalone
``BundleVerifier`` that checks a local evidence bundle's file integrity.
"""

from .engine import DecisionEngine, DecisionEngineError, RulePackError
from .rules import (
    AmbiguousScopeError,
    ConflictingBindingError,
    RuleEvaluationError,
    UnparseableTimeError,
    evaluate_demo_bind_time,
)
from .verifier import BundleVerifier

__all__ = [
    "AmbiguousScopeError",
    "BundleVerifier",
    "ConflictingBindingError",
    "DecisionEngine",
    "DecisionEngineError",
    "RuleEvaluationError",
    "RulePackError",
    "UnparseableTimeError",
    "evaluate_demo_bind_time",
]
