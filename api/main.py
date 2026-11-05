"""Aplicação FastAPI para exposição dos logs, anomalias, estatísticas e execução do pipeline (SEC-11 / SEC-12)."""

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from api.schemas import (
    ExplainResponse,
    HealthResponse,
    LogEventSchema,
    PaginatedLogsResponse,
    PipelineRunRequest,
    PipelineRunResponse,
    SummaryStatsResponse,
)
from secops_core.config import get_settings
from secops_core.db import SecOpsDatabase
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.pipeline import run_detection_pipeline

app = FastAPI(
    title="SecOps Assistido por IA — API Local (Mãos na Tech)",
    description=(
        "API REST para consulta de eventos estilo AWS CloudTrail, detecção híbrida de anomalias "
        "(Z-Score, Isolation Forest, Regras CloudTrail) e explicações em linguagem simples via Ollama/Jinja2."
    ),
    version="1.0.0",
)


def _get_db() -> SecOpsDatabase:
    db_path = os.getenv("SQLITE_DB_PATH") or str(get_settings().sqlite_db_path)
    return SecOpsDatabase(db_path=db_path)


@app.get("/health", response_model=HealthResponse, tags=["Monitoramento"])
def healthcheck() -> HealthResponse:
    """Retorna o status operacional da API, do banco SQLite e do servidor Ollama local."""
    db = _get_db()
    stats = db.get_summary_stats()
    explainer = OllamaExplainerClient()
    ollama_status = explainer.check_health(use_cache=True)
    return HealthResponse(
        status="ok",
        sqlite_connected=True,
        sqlite_db_path=str(db.db_path),
        total_logs_in_db=stats["total_logs"],
        ollama=ollama_status,
    )


@app.get("/stats", response_model=SummaryStatsResponse, tags=["Métricas & KPIs"])
def get_stats() -> SummaryStatsResponse:
    """Retorna o resumo executivo de logs analisados, anomalias, severidade e detectores."""
    db = _get_db()
    stats = db.get_summary_stats()
    return SummaryStatsResponse(**stats)


@app.get("/logs", response_model=PaginatedLogsResponse, tags=["Logs & Alertas"])
def list_logs(
    is_anomaly: Optional[bool] = Query(default=None, description="Filtra apenas anomalias (true) ou normais (false)"),
    severity: Optional[str] = Query(default=None, description="Filtra por severidade (CRITICAL, HIGH, MEDIUM, LOW)"),
    event_name: Optional[str] = Query(default=None, description="Filtra pelo nome do evento CloudTrail"),
    user: Optional[str] = Query(default=None, description="Filtra pelo nome do usuário AWS"),
    source_ip: Optional[str] = Query(default=None, description="Filtra pelo endereço IP de origem"),
    detector_type: Optional[str] = Query(
        default=None,
        description="Filtra pelo detector que sinalizou (ZSCORE, IFOREST, CLOUDTRAIL)",
    ),
    limit: int = Query(default=100, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> PaginatedLogsResponse:
    """Lista logs processados com suporte a múltiplos filtros combinados e paginação."""
    db = _get_db()
    items = db.query_logs(
        is_anomaly=is_anomaly,
        severity=severity,
        event_name=event_name,
        user_name=user,
        source_ip=source_ip,
        detector_type=detector_type,
        limit=limit,
        offset=offset,
    )
    return PaginatedLogsResponse(
        count=len(items),
        limit=limit,
        offset=offset,
        items=[LogEventSchema(**item) for item in items],
    )


@app.get("/anomalies/{event_id}", response_model=LogEventSchema, tags=["Logs & Alertas"])
def get_anomaly_detail(event_id: str) -> LogEventSchema:
    """Retorna os detalhes completos de um evento/alerta específico incluindo a explicação da IA."""
    db = _get_db()
    record = db.get_by_event_id(event_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Evento '{event_id}' não encontrado no banco SQLite.")
    return LogEventSchema(**record)


@app.post("/pipeline/run", response_model=PipelineRunResponse, tags=["Orquestração"])
def trigger_pipeline(payload: PipelineRunRequest) -> PipelineRunResponse:
    """Dispara sob demanda a geração opcional de logs, detecção híbrida e persistência SQLite."""
    db = _get_db()
    logs_path = os.getenv("LOGS_JSONL_PATH") or str(get_settings().logs_jsonl_path)
    result = run_detection_pipeline(
        logs_path=logs_path,
        db_path=db.db_path,
        regenerate_logs=payload.regenerate_logs,
        total_records=payload.total_records,
        anomaly_rate=payload.anomaly_rate,
        seed=payload.seed,
        generate_explanations=payload.generate_explanations,
    )
    return PipelineRunResponse(**result)


@app.post("/anomalies/{event_id}/explain", response_model=ExplainResponse, tags=["IA Local (Ollama/Jinja2)"])
def explain_anomaly(event_id: str) -> ExplainResponse:
    """Gera ou atualiza sob demanda a explicação em linguagem simples via Ollama/Jinja2 para o alerta."""
    db = _get_db()
    record = db.get_by_event_id(event_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Evento '{event_id}' não encontrado.")

    explainer = OllamaExplainerClient()
    health = explainer.check_health(use_cache=True)
    explanation = explainer.explain_alert(record)
    db.update_ai_explanation(event_id, explanation)
    return ExplainResponse(
        event_id=event_id,
        ai_explanation=explanation,
        mode=health["mode"],
    )
