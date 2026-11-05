"""Camada de persistência SQLite para logs processados e alertas SecOps (SEC-04).

Gerencia conexão local a custo zero, criação automática de tabelas e índices,
inserção em lote idempotente (UPSERT por event_id), atualização de explicação da IA
e consultas filtradas de alta performance (< 100ms para 5.000 registros).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from secops_core.config import get_settings

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS processed_logs (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_name TEXT NOT NULL,
    event_source TEXT NOT NULL,
    event_category TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_type TEXT NOT NULL,
    user_role TEXT NOT NULL,
    user_arn TEXT,
    mfa_authenticated INTEGER NOT NULL DEFAULT 0,
    source_ip TEXT NOT NULL,
    aws_region TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT,
    request_count INTEGER NOT NULL DEFAULT 1,
    bytes_transferred INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL NOT NULL DEFAULT 0.0,
    user_agent TEXT,
    resource_arn TEXT,
    hour_of_day INTEGER NOT NULL DEFAULT 0,
    day_of_week INTEGER NOT NULL DEFAULT 0,
    is_off_hours INTEGER NOT NULL DEFAULT 0,
    is_error INTEGER NOT NULL DEFAULT 0,
    is_external_ip INTEGER NOT NULL DEFAULT 0,
    is_atypical_region INTEGER NOT NULL DEFAULT 0,
    zscore_value REAL NOT NULL DEFAULT 0.0,
    is_zscore_anomaly INTEGER NOT NULL DEFAULT 0,
    iforest_score REAL NOT NULL DEFAULT 0.0,
    is_iforest_anomaly INTEGER NOT NULL DEFAULT 0,
    cloudtrail_rules_triggered TEXT NOT NULL DEFAULT '[]',
    is_cloudtrail_anomaly INTEGER NOT NULL DEFAULT 0,
    final_severity TEXT NOT NULL DEFAULT 'LOW',
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    ai_explanation TEXT,
    raw_metadata TEXT NOT NULL DEFAULT '{}',
    processed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processed_logs_timestamp ON processed_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_processed_logs_is_anomaly ON processed_logs(is_anomaly);
CREATE INDEX IF NOT EXISTS idx_processed_logs_final_severity ON processed_logs(final_severity);
CREATE INDEX IF NOT EXISTS idx_processed_logs_event_name ON processed_logs(event_name);
CREATE INDEX IF NOT EXISTS idx_processed_logs_source_ip ON processed_logs(source_ip);

CREATE VIEW IF NOT EXISTS security_alerts AS
SELECT * FROM processed_logs WHERE is_anomaly = 1;
"""


class SecOpsDatabase:
    """Repositório SQLite para persistência e consulta de logs e anomalias."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        settings = get_settings()
        self.db_path = Path(db_path) if db_path is not None else settings.sqlite_db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Gerencia conexão SQLite com WAL e retorno em formato dict-like (Row)."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Cria tabelas, índices e view se ainda não existirem."""
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def bulk_upsert_logs(self, records: Iterable[Dict[str, Any]]) -> int:
        """Insere ou atualiza registros em lote com idempotência por event_id."""
        now_iso = datetime.now(timezone.utc).isoformat()
        rows_to_insert: List[tuple] = []

        for rec in records:
            rules = rec.get("cloudtrail_rules_triggered", [])
            rules_json = json.dumps(rules, ensure_ascii=False) if not isinstance(rules, str) else rules
            raw_meta = rec.get("raw_metadata", {})
            meta_json = json.dumps(raw_meta, ensure_ascii=False) if not isinstance(raw_meta, str) else raw_meta

            is_ct_anom = int(bool(rec.get("is_cloudtrail_anomaly", bool(rules and rules != "[]"))))
            is_zs_anom = int(bool(rec.get("is_zscore_anomaly", False)))
            is_if_anom = int(bool(rec.get("is_iforest_anomaly", False)))
            is_anom = int(bool(rec.get("is_anomaly", is_zs_anom or is_if_anom or is_ct_anom)))

            rows_to_insert.append(
                (
                    str(rec["event_id"]),
                    str(rec.get("timestamp_iso") or rec["timestamp"]),
                    str(rec["event_name"]),
                    str(rec["event_source"]),
                    str(rec.get("event_category", "UNKNOWN")),
                    str(rec.get("user_name", "unknown")),
                    str(rec.get("user_type", "IAMUser")),
                    str(rec.get("user_role", "Standard")),
                    str(rec.get("user_arn", "")),
                    int(bool(rec.get("mfa_authenticated", False))),
                    str(rec["source_ip"]),
                    str(rec.get("aws_region", "sa-east-1")),
                    str(rec.get("status", "SUCCESS")),
                    rec.get("error_code"),
                    int(rec.get("request_count", 1)),
                    int(rec.get("bytes_transferred", 0)),
                    float(rec.get("latency_ms", 0.0)),
                    str(rec.get("user_agent", "")),
                    str(rec.get("resource_arn", "")),
                    int(rec.get("hour_of_day", 0)),
                    int(rec.get("day_of_week", 0)),
                    int(rec.get("is_off_hours", 0)),
                    int(rec.get("is_error", 0)),
                    int(rec.get("is_external_ip", 0)),
                    int(rec.get("is_atypical_region", 0)),
                    float(rec.get("zscore_value", 0.0)),
                    is_zs_anom,
                    float(rec.get("iforest_score", 0.0)),
                    is_if_anom,
                    rules_json,
                    is_ct_anom,
                    str(rec.get("final_severity", "LOW")),
                    is_anom,
                    rec.get("ai_explanation"),
                    meta_json,
                    str(rec.get("processed_at") or now_iso),
                )
            )

        if not rows_to_insert:
            return 0

        sql = """
        INSERT INTO processed_logs (
            event_id, timestamp, event_name, event_source, event_category,
            user_name, user_type, user_role, user_arn, mfa_authenticated,
            source_ip, aws_region, status, error_code,
            request_count, bytes_transferred, latency_ms, user_agent, resource_arn,
            hour_of_day, day_of_week, is_off_hours, is_error, is_external_ip, is_atypical_region,
            zscore_value, is_zscore_anomaly, iforest_score, is_iforest_anomaly,
            cloudtrail_rules_triggered, is_cloudtrail_anomaly,
            final_severity, is_anomaly, ai_explanation, raw_metadata, processed_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        ON CONFLICT(event_id) DO UPDATE SET
            timestamp=excluded.timestamp,
            event_name=excluded.event_name,
            event_source=excluded.event_source,
            event_category=excluded.event_category,
            user_name=excluded.user_name,
            user_type=excluded.user_type,
            user_role=excluded.user_role,
            user_arn=excluded.user_arn,
            mfa_authenticated=excluded.mfa_authenticated,
            source_ip=excluded.source_ip,
            aws_region=excluded.aws_region,
            status=excluded.status,
            error_code=excluded.error_code,
            request_count=excluded.request_count,
            bytes_transferred=excluded.bytes_transferred,
            latency_ms=excluded.latency_ms,
            user_agent=excluded.user_agent,
            resource_arn=excluded.resource_arn,
            hour_of_day=excluded.hour_of_day,
            day_of_week=excluded.day_of_week,
            is_off_hours=excluded.is_off_hours,
            is_error=excluded.is_error,
            is_external_ip=excluded.is_external_ip,
            is_atypical_region=excluded.is_atypical_region,
            zscore_value=excluded.zscore_value,
            is_zscore_anomaly=excluded.is_zscore_anomaly,
            iforest_score=excluded.iforest_score,
            is_iforest_anomaly=excluded.is_iforest_anomaly,
            cloudtrail_rules_triggered=excluded.cloudtrail_rules_triggered,
            is_cloudtrail_anomaly=excluded.is_cloudtrail_anomaly,
            final_severity=excluded.final_severity,
            is_anomaly=excluded.is_anomaly,
            ai_explanation=COALESCE(excluded.ai_explanation, processed_logs.ai_explanation),
            raw_metadata=excluded.raw_metadata,
            processed_at=excluded.processed_at;
        """
        with self.connect() as conn:
            conn.executemany(sql, rows_to_insert)
        return len(rows_to_insert)

    def update_ai_explanation(self, event_id: str, explanation: str) -> bool:
        """Atualiza a explicação gerada pela IA para um alerta específico."""
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE processed_logs SET ai_explanation = ? WHERE event_id = ?",
                (explanation, event_id),
            )
            return cur.rowcount > 0

    def get_by_event_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Busca um evento/alerta específico pelo event_id."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM processed_logs WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            return self._deserialize_row(row) if row else None

    def query_logs(
        self,
        is_anomaly: Optional[bool] = None,
        severity: Optional[str] = None,
        event_name: Optional[str] = None,
        user_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        detector_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Consulta filtrada e paginada de logs/anomalias."""
        clauses: List[str] = []
        params: List[Any] = []

        if is_anomaly is not None:
            clauses.append("is_anomaly = ?")
            params.append(1 if is_anomaly else 0)
        if severity:
            clauses.append("final_severity = ?")
            params.append(severity.upper())
        if event_name:
            clauses.append("event_name = ?")
            params.append(event_name)
        if user_name:
            clauses.append("user_name = ?")
            params.append(user_name)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if detector_type:
            dt = detector_type.upper()
            if dt in ("ZSCORE", "Z-SCORE"):
                clauses.append("is_zscore_anomaly = 1")
            elif dt in ("IFOREST", "ISOLATION_FOREST", "ML"):
                clauses.append("is_iforest_anomaly = 1")
            elif dt in ("CLOUDTRAIL", "RULES", "RULE"):
                clauses.append("is_cloudtrail_anomaly = 1")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT * FROM processed_logs
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([int(limit), int(offset)])

        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_row(r) for r in rows]

    def get_summary_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas agregadas de logs, anomalias, severidades e detectores."""
        with self.connect() as conn:
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_logs,
                    COALESCE(SUM(is_anomaly), 0) AS total_anomalies,
                    COALESCE(SUM(is_zscore_anomaly), 0) AS zscore_count,
                    COALESCE(SUM(is_iforest_anomaly), 0) AS iforest_count,
                    COALESCE(SUM(is_cloudtrail_anomaly), 0) AS cloudtrail_count
                FROM processed_logs
                """
            ).fetchone()

            sev_rows = conn.execute(
                """
                SELECT final_severity, COUNT(*) AS cnt
                FROM processed_logs
                WHERE is_anomaly = 1
                GROUP BY final_severity
                """
            ).fetchall()

            top_ips = conn.execute(
                """
                SELECT source_ip, COUNT(*) AS cnt
                FROM processed_logs
                WHERE is_anomaly = 1
                GROUP BY source_ip
                ORDER BY cnt DESC
                LIMIT 5
                """
            ).fetchall()

            top_events = conn.execute(
                """
                SELECT event_name, COUNT(*) AS cnt
                FROM processed_logs
                WHERE is_anomaly = 1
                GROUP BY event_name
                ORDER BY cnt DESC
                LIMIT 5
                """
            ).fetchall()

        total_logs = int(totals["total_logs"] or 0)
        total_anomalies = int(totals["total_anomalies"] or 0)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in sev_rows:
            severity_counts[r["final_severity"]] = int(r["cnt"])

        return {
            "total_logs": total_logs,
            "total_anomalies": total_anomalies,
            "anomaly_rate": round(total_anomalies / max(1, total_logs), 4),
            "by_severity": severity_counts,
            "by_detector": {
                "zscore": int(totals["zscore_count"] or 0),
                "isolation_forest": int(totals["iforest_count"] or 0),
                "cloudtrail_rules": int(totals["cloudtrail_count"] or 0),
            },
            "top_suspicious_ips": [{"source_ip": r["source_ip"], "count": int(r["cnt"])} for r in top_ips],
            "top_anomalous_events": [{"event_name": r["event_name"], "count": int(r["cnt"])} for r in top_events],
        }

    @staticmethod
    def _deserialize_row(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        for bool_field in (
            "mfa_authenticated",
            "is_off_hours",
            "is_error",
            "is_external_ip",
            "is_atypical_region",
            "is_zscore_anomaly",
            "is_iforest_anomaly",
            "is_cloudtrail_anomaly",
            "is_anomaly",
        ):
            if bool_field in data:
                data[bool_field] = bool(data[bool_field])

        for json_field, default in (("cloudtrail_rules_triggered", []), ("raw_metadata", {})):
            raw_val = data.get(json_field)
            if isinstance(raw_val, str):
                try:
                    data[json_field] = json.loads(raw_val)
                except json.JSONDecodeError:
                    data[json_field] = default
        return data
