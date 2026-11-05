"""Detector de anomalias multivariadas com Isolation Forest (SEC-06).

Utiliza sklearn.ensemble.IsolationForest sobre a matriz de features extraída pelo LGMS
com escalonamento StandardScaler e reprodutibilidade garantida por random_state fixo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from secops_core.config import get_settings
from secops_core.lgms import LGMSRecord, extract_feature_matrix


@dataclass(frozen=True)
class IsolationForestResult:
    """Resultado individual da predição do Isolation Forest para um evento."""

    event_id: str
    iforest_score: float
    is_iforest_anomaly: bool


class IsolationForestDetector:
    """Detector não supervisionado de anomalias multivariadas baseado em Isolation Forest."""

    def __init__(
        self,
        contamination: Optional[float] = None,
        n_estimators: int = 150,
        random_state: int = 42,
    ) -> None:
        settings = get_settings()
        self.contamination = float(
            contamination if contamination is not None else settings.iforest_contamination
        )
        if not (0.0 < self.contamination <= 0.5):
            raise ValueError("contamination deve estar no intervalo (0.0, 0.5].")
        self.n_estimators = int(n_estimators)
        self.random_state = int(random_state)
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        )
        self._is_fitted = False

    def fit(self, records: Iterable[LGMSRecord]) -> "IsolationForestDetector":
        """Treina o escalonador e o modelo Isolation Forest sobre registros LGMS."""
        rec_list = list(records)
        if not rec_list:
            raise ValueError("Não é possível treinar IsolationForest com lista vazia.")

        matrix, _ = extract_feature_matrix(rec_list)
        x_scaled = self.scaler.fit_transform(np.asarray(matrix, dtype=np.float64))
        self.model.fit(x_scaled)
        self._is_fitted = True
        return self

    def score_records(self, records: Iterable[LGMSRecord]) -> List[IsolationForestResult]:
        """Infere classificação binária (-1 -> anomalia) e decision_function contínuo."""
        rec_list = list(records)
        if not rec_list:
            return []

        if not self._is_fitted:
            self.fit(rec_list)

        matrix, _ = extract_feature_matrix(rec_list)
        x_scaled = self.scaler.transform(np.asarray(matrix, dtype=np.float64))
        preds = self.model.predict(x_scaled)
        scores = self.model.decision_function(x_scaled)

        results: List[IsolationForestResult] = []
        for rec, pred, score in zip(rec_list, preds, scores):
            results.append(
                IsolationForestResult(
                    event_id=rec.event_id,
                    iforest_score=round(float(score), 4),
                    is_iforest_anomaly=bool(int(pred) == -1),
                )
            )
        return results

    def fit_predict(self, records: Iterable[LGMSRecord]) -> List[IsolationForestResult]:
        """Treina e infere sobre o mesmo lote de registros LGMS."""
        rec_list = list(records)
        self.fit(rec_list)
        return self.score_records(rec_list)
