"""Subpacote de detectores de anomalias (Z-Score, Isolation Forest e Regras CloudTrail)."""

from secops_core.detectors.cloudtrail_rules import CloudTrailRuleEngine, TriggeredRule
from secops_core.detectors.isolation_forest import IsolationForestDetector, IsolationForestResult
from secops_core.detectors.zscore_detector import ZScoreDetector, ZScoreResult

__all__ = [
    "CloudTrailRuleEngine",
    "TriggeredRule",
    "IsolationForestDetector",
    "IsolationForestResult",
    "ZScoreDetector",
    "ZScoreResult",
]
