"""Orquestrador do pipeline híbrido de detecção SecOps e persistência SQLite (SEC-08).

Executa de ponta a ponta:
1. Geração opcional de logs sintéticos (logs_simulados.jsonl)
2. Modelagem e extração de features via LGMS
3. Detecção combinada (Z-Score + Isolation Forest + Regras CloudTrail)
4. Fusão de decisão (Ensemble) e cálculo de severidade final
5. Persistência transacional no SQLite e explicação opcional via IA local
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from secops_core.config import get_settings
from secops_core.db import SecOpsDatabase
from secops_core.detectors.cloudtrail_rules import CloudTrailRuleEngine, TriggeredRule
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.zscore_detector import ZScoreDetector
from secops_core.generator import generate_synthetic_logs
from secops_core.lgms import parse_jsonl_logs

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def consolidate_severity(
    is_zscore: bool,
    zscore_val: float,
    is_iforest: bool,
    iforest_score: float,
    triggered_rules: List[TriggeredRule],
) -> tuple[bool, str]:
    """Consolida o veredito dos 3 detectores em (is_anomaly, final_severity)."""
    is_ct = len(triggered_rules) > 0
    is_anomaly = bool(is_zscore or is_iforest or is_ct)

    if not is_anomaly:
        return False, "LOW"

    active_detectors = int(is_zscore) + int(is_iforest) + int(is_ct)
    max_rule_sev = "LOW"
    for r in triggered_rules:
        if SEVERITY_RANK.get(r.severity, 1) > SEVERITY_RANK.get(max_rule_sev, 1):
            max_rule_sev = r.severity

    # Se uma regra CRITICAL disparou ou todos os 3 motores sinalizaram simultaneamente -> CRITICAL
    if max_rule_sev == "CRITICAL" or active_detectors == 3:
        return True, "CRITICAL"

    # Se 2 motores sinalizaram ou há regra HIGH ou Z-Score extremo (> 6.0) -> HIGH
    if active_detectors >= 2 or max_rule_sev == "HIGH" or zscore_val >= 6.0:
        return True, "HIGH"

    # Se apenas 1 detector (Z-Score moderado ou Isolation Forest isolado) -> MEDIUM
    if is_zscore or (is_iforest and iforest_score < -0.05):
        return True, "MEDIUM"

    return True, "LOW"


def run_detection_pipeline(
    logs_path: Optional[str | Path] = None,
    db_path: Optional[str | Path] = None,
    regenerate_logs: bool = False,
    total_records: int = 1500,
    anomaly_rate: float = 0.06,
    seed: int = 42,
    generate_explanations: bool = False,
    max_explanations: int = 100,
) -> Dict[str, Any]:
    """Executa o pipeline completo de ingestão, detecção híbrida e gravação no SQLite.

    O banco passa a refletir exatamente o dataset processado (eventos que não estão mais
    no JSONL são removidos). Explicações de IA já persistidas são reaproveitadas e no
    máximo `max_explanations` novas explicações são geradas por execução (CRITICAL primeiro),
    evitando bloquear a API/painel em lotes grandes com o Ollama ativo.
    """
    t_start = time.perf_counter()
    settings = get_settings()
    target_logs_path = Path(logs_path) if logs_path is not None else settings.logs_jsonl_path
    target_db_path = Path(db_path) if db_path is not None else settings.sqlite_db_path

    if regenerate_logs or not target_logs_path.exists():
        generate_synthetic_logs(
            output_path=target_logs_path,
            total_records=total_records,
            anomaly_rate=anomaly_rate,
            seed=seed,
        )

    records, skipped_lines = parse_jsonl_logs(target_logs_path)
    if not records:
        return {
            "status": "empty",
            "logs_path": str(target_logs_path),
            "db_path": str(target_db_path),
            "records_processed": 0,
            "skipped_lines": skipped_lines,
            "anomalies_detected": 0,
            "anomaly_rate": 0.0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_detector": {"zscore": 0, "isolation_forest": 0, "cloudtrail_rules": 0},
            "explanations_generated": 0,
            "elapsed_ms": round((time.perf_counter() - t_start) * 1000, 2),
        }

    # 1. Detector Estatístico (Z-Score)
    zscore_detector = ZScoreDetector(threshold=settings.zscore_threshold)
    zscore_results = zscore_detector.fit_predict(records)

    # 2. Detector de Machine Learning (Isolation Forest)
    iforest_detector = IsolationForestDetector(
        contamination=settings.iforest_contamination,
        random_state=seed,
    )
    iforest_results = iforest_detector.fit_predict(records)

    # 3. Motor de Regras Determinísticas (CloudTrail)
    rule_engine = CloudTrailRuleEngine()

    now_iso = datetime.now(timezone.utc).isoformat()
    enriched_rows: List[Dict[str, Any]] = []

    for rec, zs_res, if_res in zip(records, zscore_results, iforest_results):
        triggered_rules = rule_engine.evaluate_record(rec)
        is_anom, final_sev = consolidate_severity(
            is_zscore=zs_res.is_zscore_anomaly,
            zscore_val=zs_res.zscore_value,
            is_iforest=if_res.is_iforest_anomaly,
            iforest_score=if_res.iforest_score,
            triggered_rules=triggered_rules,
        )

        row_dict = rec.to_dict()
        row_dict.update(
            {
                "zscore_value": zs_res.zscore_value,
                "is_zscore_anomaly": zs_res.is_zscore_anomaly,
                "iforest_score": if_res.iforest_score,
                "is_iforest_anomaly": if_res.is_iforest_anomaly,
                "cloudtrail_rules_triggered": [r.to_dict() for r in triggered_rules],
                "is_cloudtrail_anomaly": len(triggered_rules) > 0,
                "final_severity": final_sev,
                "is_anomaly": is_anom,
                "processed_at": now_iso,
            }
        )
        enriched_rows.append(row_dict)

    db = SecOpsDatabase(target_db_path)

    # 4. Explicações via IA Local (reaproveita as já persistidas; gera no máximo `max_explanations` novas)
    explanations_generated = 0
    if generate_explanations:
        from secops_core.explainer.ollama_client import OllamaExplainerClient

        anomalous_rows = [row for row in enriched_rows if row["is_anomaly"]]
        existing = db.get_explanations(row["event_id"] for row in anomalous_rows)
        pending = [row for row in anomalous_rows if row["event_id"] not in existing]
        pending.sort(key=lambda row: SEVERITY_RANK.get(row["final_severity"], 0), reverse=True)

        explainer = OllamaExplainerClient()
        for row in pending[: max(0, int(max_explanations))]:
            row["ai_explanation"] = explainer.explain_alert(row)
            explanations_generated += 1

    # 5. Persistência SQLite (o banco passa a refletir exatamente o dataset processado)
    upserted = db.bulk_upsert_logs(enriched_rows, replace_dataset=True)

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_detector = {"zscore": 0, "isolation_forest": 0, "cloudtrail_rules": 0}
    anomalies_detected = 0
    for row in enriched_rows:
        if not row["is_anomaly"]:
            continue
        anomalies_detected += 1
        by_severity[row["final_severity"]] = by_severity.get(row["final_severity"], 0) + 1
    for row in enriched_rows:
        by_detector["zscore"] += int(bool(row["is_zscore_anomaly"]))
        by_detector["isolation_forest"] += int(bool(row["is_iforest_anomaly"]))
        by_detector["cloudtrail_rules"] += int(bool(row["is_cloudtrail_anomaly"]))

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        "status": "success",
        "logs_path": str(target_logs_path),
        "db_path": str(target_db_path),
        "records_processed": upserted,
        "skipped_lines": skipped_lines,
        "anomalies_detected": anomalies_detected,
        "anomaly_rate": round(anomalies_detected / max(1, len(enriched_rows)), 4),
        "by_severity": by_severity,
        "by_detector": by_detector,
        "explanations_generated": explanations_generated,
        "elapsed_ms": elapsed_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa o pipeline híbrido de detecção SecOps (LGMS + Z-Score + Isolation Forest + CloudTrail -> SQLite)"
    )
    parser.add_argument("--logs", type=str, default=None, help="Caminho para logs_simulados.jsonl")
    parser.add_argument("--db", type=str, default=None, help="Caminho para o banco SQLite")
    parser.add_argument("--regenerate", action="store_true", help="Regenera os logs sintéticos antes de rodar")
    parser.add_argument("--count", type=int, default=1500, help="Quantidade de logs ao regenerar")
    parser.add_argument("--anomaly-rate", type=float, default=0.06, help="Taxa de anomalias ao regenerar")
    parser.add_argument("--seed", type=int, default=42, help="Semente aleatória (geração e Isolation Forest)")
    parser.add_argument("--explain", action="store_true", help="Gera explicações via IA/Fallback para as anomalias")
    parser.add_argument(
        "--max-explanations",
        type=int,
        default=100,
        help="Máximo de novas explicações geradas nesta execução (default: 100)",
    )
    args = parser.parse_args()

    result = run_detection_pipeline(
        logs_path=args.logs,
        db_path=args.db,
        regenerate_logs=args.regenerate,
        total_records=args.count,
        anomaly_rate=args.anomaly_rate,
        seed=args.seed,
        generate_explanations=args.explain,
        max_explanations=args.max_explanations,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
