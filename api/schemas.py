"""Schemas Pydantic para contratos de entrada e saída da API FastAPI (SEC-11 / SEC-12)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TriggeredRuleSchema(BaseModel):
    rule_code: str
    rule_name: str
    severity: str
    reason: str


class LogEventSchema(BaseModel):
    event_id: str
    timestamp: str
    event_name: str
    event_source: str
    event_category: str
    user_name: str
    user_type: str
    user_role: str
    user_arn: Optional[str] = ""
    mfa_authenticated: bool
    source_ip: str
    aws_region: str
    status: str
    error_code: Optional[str] = None
    request_count: int
    bytes_transferred: int
    latency_ms: float
    user_agent: Optional[str] = ""
    resource_arn: Optional[str] = ""
    hour_of_day: int
    day_of_week: int
    is_off_hours: bool
    is_error: bool
    is_external_ip: bool
    is_atypical_region: bool
    zscore_value: float
    is_zscore_anomaly: bool
    iforest_score: float
    is_iforest_anomaly: bool
    cloudtrail_rules_triggered: List[TriggeredRuleSchema] = Field(default_factory=list)
    is_cloudtrail_anomaly: bool
    final_severity: str
    is_anomaly: bool
    ai_explanation: Optional[str] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    processed_at: str


class HealthResponse(BaseModel):
    status: str
    sqlite_connected: bool
    sqlite_db_path: str
    total_logs_in_db: int
    ollama: Dict[str, Any]


class SummaryStatsResponse(BaseModel):
    total_logs: int
    total_anomalies: int
    anomaly_rate: float
    by_severity: Dict[str, int]
    by_detector: Dict[str, int]
    top_suspicious_ips: List[Dict[str, Any]]
    top_anomalous_events: List[Dict[str, Any]]


class PaginatedLogsResponse(BaseModel):
    count: int
    limit: int
    offset: int
    items: List[LogEventSchema]


class PipelineRunRequest(BaseModel):
    regenerate_logs: bool = Field(
        default=False,
        description="Se True, gera um novo arquivo logs_simulados.jsonl antes de rodar os detectores.",
    )
    total_records: int = Field(default=1500, ge=50, le=20000)
    anomaly_rate: float = Field(default=0.06, ge=0.01, le=0.45)
    seed: int = Field(default=42)
    generate_explanations: bool = Field(default=True)


class PipelineRunResponse(BaseModel):
    status: str
    logs_path: str
    db_path: str
    records_processed: int
    skipped_lines: int
    anomalies_detected: int
    anomaly_rate: float
    by_severity: Dict[str, int]
    by_detector: Dict[str, int]
    explanations_generated: int
    elapsed_ms: float


class ExplainResponse(BaseModel):
    event_id: str
    ai_explanation: str
    mode: str
