"""Aplicação FastAPI para exposição dos logs, anomalias, estatísticas e execução do pipeline (SEC-11 / SEC-12)."""

from __future__ import annotations

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


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_DETECTORS = {"ZSCORE", "Z-SCORE", "IFOREST", "ISOLATION_FOREST", "ML", "CLOUDTRAIL", "RULES", "RULE"}


def _get_db() -> SecOpsDatabase:
    return SecOpsDatabase(db_path=get_settings().sqlite_db_path)


def _validation_error(param: str, message: str, value: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail=[{"type": "value_error", "loc": ["query", param], "msg": message, "input": value}],
    )


@app.get("/health", response_model=HealthResponse, tags=["Monitoramento"])
def healthcheck() -> HealthResponse:
    """Retorna o status operacional da API, do banco SQLite e do servidor Ollama local."""
    db_path = get_settings().sqlite_db_path
    try:
        db = SecOpsDatabase(db_path=db_path)
        total_logs = db.get_summary_stats()["total_logs"]
        sqlite_ok = True
    except Exception:
        total_logs = 0
        sqlite_ok = False
    ollama_status = OllamaExplainerClient().check_health(use_cache=True)
    return HealthResponse(
        status="ok" if sqlite_ok else "degraded",
        sqlite_connected=sqlite_ok,
        sqlite_db_path=str(db_path),
        total_logs_in_db=total_logs,
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
    if severity and severity.upper() not in VALID_SEVERITIES:
        raise _validation_error("severity", "Use CRITICAL, HIGH, MEDIUM ou LOW.", severity)
    if detector_type and detector_type.upper() not in VALID_DETECTORS:
        raise _validation_error("detector_type", "Use ZSCORE, IFOREST ou CLOUDTRAIL.", detector_type)
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
    settings = get_settings()
    result = run_detection_pipeline(
        logs_path=settings.logs_jsonl_path,
        db_path=settings.sqlite_db_path,
        regenerate_logs=payload.regenerate_logs,
        total_records=payload.total_records,
        anomaly_rate=payload.anomaly_rate,
        seed=payload.seed,
        generate_explanations=payload.generate_explanations,
        max_explanations=payload.max_explanations,
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
    explanation = explainer.explain_alert(record)
    db.update_ai_explanation(event_id, explanation)
    # Consultado após a geração: reflete fallback acionado por falha/timeout durante a chamada
    health = explainer.check_health(use_cache=True)
    return ExplainResponse(
        event_id=event_id,
        ai_explanation=explanation,
        mode=health["mode"],
    )
