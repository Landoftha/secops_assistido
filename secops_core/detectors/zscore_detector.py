"""Detector estatístico de anomalias volumétricas e temporais via Z-Score (SEC-05).

Calcula Z = (x - μ) / σ sobre métricas volumétricas e de latência extraídas pelo LGMS,
com proteção contra desvio padrão zero (σ = 0) e limiar configurável (default |Z| > 3.0).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

from secops_core.config import get_settings
from secops_core.lgms import LGMSRecord

DEFAULT_ZSCORE_METRICS: Sequence[str] = (
    "request_count",
    "bytes_transferred",
    "latency_ms",
    "ip_window_frequency",
)


@dataclass(frozen=True)
class ZScoreResult:
    """Resultado individual da avaliação Z-Score para um evento."""

    event_id: str
    zscore_value: float
    is_zscore_anomaly: bool
    triggered_metric: str
    metric_zscores: Dict[str, float]


class ZScoreDetector:
    """Detector estatístico baseado em Z-Score multivariado por métrica."""

    def __init__(
        self,
        threshold: float | None = None,
        metrics: Sequence[str] = DEFAULT_ZSCORE_METRICS,
    ) -> None:
        settings = get_settings()
        self.threshold = float(threshold if threshold is not None else settings.zscore_threshold)
        if self.threshold <= 0:
            raise ValueError("O limiar (threshold) do Z-Score deve ser positivo.")
        self.metrics = tuple(metrics)
        self.stats_: Dict[str, Dict[str, float]] = {}

    @staticmethod
    def _compute_mean_std(values: List[float]) -> tuple[float, float]:
        n = len(values)
        if n == 0:
            return 0.0, 0.0
        mean_val = sum(values) / n
        if n < 2:
            return mean_val, 0.0
        variance = sum((x - mean_val) ** 2 for x in values) / (n - 1)
        return mean_val, math.sqrt(variance)

    def fit(self, records: Iterable[LGMSRecord]) -> "ZScoreDetector":
        """Calcula média (μ) e desvio padrão amostral (σ) para cada métrica monitorada."""
        rec_list = list(records)
        self.stats_ = {}
        for metric in self.metrics:
            vals = [float(getattr(r, metric, 0.0)) for r in rec_list]
            mean_val, std_val = self._compute_mean_std(vals)
            self.stats_[metric] = {"mean": mean_val, "std": std_val}
        return self

    def score_records(self, records: Iterable[LGMSRecord]) -> List[ZScoreResult]:
        """Calcula o Z-Score máximo absoluto por evento sem mutar os objetos originais."""
        rec_list = list(records)
        if not rec_list:
            return []

        if not self.stats_:
            self.fit(rec_list)

        results: List[ZScoreResult] = []
        for rec in rec_list:
            metric_scores: Dict[str, float] = {}
            max_abs_z = 0.0
            dominant_metric = self.metrics[0] if self.metrics else "request_count"

            for metric in self.metrics:
                val = float(getattr(rec, metric, 0.0))
                stat = self.stats_.get(metric, {"mean": 0.0, "std": 0.0})
                std_val = stat["std"]
                if std_val <= 1e-12:
                    z = 0.0
                else:
                    z = (val - stat["mean"]) / std_val

                z_abs = abs(z)
                metric_scores[metric] = round(z, 4)
                if z_abs >= max_abs_z:
                    max_abs_z = z_abs
                    dominant_metric = metric

            is_anom = max_abs_z > self.threshold
            results.append(
                ZScoreResult(
                    event_id=rec.event_id,
                    zscore_value=round(max_abs_z, 4),
                    is_zscore_anomaly=is_anom,
                    triggered_metric=dominant_metric,
                    metric_zscores=metric_scores,
                )
            )
        return results

    def fit_predict(self, records: Iterable[LGMSRecord]) -> List[ZScoreResult]:
        """Ajusta os parâmetros estatísticos no lote e retorna as avaliações."""
        rec_list = list(records)
        self.fit(rec_list)
        return self.score_records(rec_list)
