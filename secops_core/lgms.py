"""Modelagem, normalização e parser de logs LGMS (Log Modeling & Schema) — SEC-03.

Responsável por validar e normalizar eventos brutos JSONL em objetos canônicos tipados
(LGMSRecord) e extrair features numéricas, temporais e comportamentais para os motores
de detecção (Z-Score, Isolation Forest e Regras CloudTrail).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

CORPORATE_SUBNETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("200.160.2.0/24"),
)

EXPECTED_REGIONS = {"sa-east-1", "us-east-1"}

CATEGORY_ENCODING = {
    "READ": 0,
    "WRITE": 1,
    "AUTH": 2,
    "DISCOVERY": 3,
    "POLICY_CHANGE": 4,
    "ADMIN": 5,
    "SECURITY_TAMPERING": 6,
    "UNKNOWN": 7,
}


def is_corporate_ip(ip_str: str) -> bool:
    """Verifica se o endereço IP pertence às redes corporativas ou gateways conhecidos."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CORPORATE_SUBNETS)
    except ValueError:
        return False


@dataclass
class LGMSRecord:
    """Modelo Canônico LGMS (Log Modeling & Schema) para um evento normalizado."""

    event_id: str
    timestamp: datetime
    timestamp_iso: str
    event_name: str
    event_source: str
    event_category: str
    user_name: str
    user_type: str
    user_role: str
    user_arn: str
    mfa_authenticated: bool
    source_ip: str
    aws_region: str
    status: str
    error_code: Optional[str]
    request_count: int
    bytes_transferred: int
    latency_ms: float
    user_agent: str
    resource_arn: str
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    # Features derivadas preenchidas pelo extrator LGMS
    hour_of_day: int = 0
    day_of_week: int = 0
    is_off_hours: int = 0
    is_error: int = 0
    is_external_ip: int = 0
    is_atypical_region: int = 0
    mfa_disabled_flag: int = 0
    category_code: int = 0
    ip_window_frequency: int = 1
    user_window_frequency: int = 1

    @classmethod
    def from_raw_dict(cls, raw: Dict[str, Any]) -> "LGMSRecord":
        """Valida e normaliza um dicionário JSON bruto para o formato canônico LGMSRecord."""
        if not isinstance(raw, dict):
            raise ValueError("O registro bruto deve ser um objeto JSON (dict).")

        required_keys = ("timestamp", "event_id", "event_name", "event_source", "source_ip")
        for key in required_keys:
            if key not in raw or raw[key] in (None, ""):
                raise ValueError(f"Campo obrigatório ausente ou vazio no log: '{key}'")

        ts_raw = str(raw["timestamp"])
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))

        identity = raw.get("user_identity") or {}
        if isinstance(identity, str):
            user_name = identity
            user_type = "IAMUser"
            user_role = "Unknown"
            user_arn = ""
            mfa_auth = False
        elif isinstance(identity, dict):
            user_name = str(identity.get("user_name") or identity.get("userName") or "unknown")
            user_type = str(identity.get("user_type") or identity.get("type") or "IAMUser")
            user_role = str(identity.get("role") or "Standard")
            user_arn = str(identity.get("arn") or "")
            mfa_auth = bool(identity.get("mfa_authenticated", False))
        else:
            raise ValueError("Formato inválido para 'user_identity'.")

        req_count = int(raw.get("request_count", raw.get("request_Count", 1)))
        bytes_trans = int(raw.get("bytes_transferred", 0))
        latency = float(raw.get("latency_ms", 50.0))
        if req_count < 0 or bytes_trans < 0 or latency < 0:
            raise ValueError("Métricas numéricas (request_count, bytes_transferred, latency_ms) não podem ser negativas.")

        status_norm = str(raw.get("status", "SUCCESS")).upper().strip()
        error_code = raw.get("error_code")
        error_code_norm = str(error_code).strip() if error_code not in (None, "") else None

        category = str(raw.get("event_category") or "UNKNOWN").upper().strip()
        source_ip = str(raw["source_ip"]).strip()
        aws_region = str(raw.get("aws_region") or "sa-east-1").strip()

        hour = ts.hour
        dow = ts.weekday()
        is_off_hours = 1 if (hour < 7 or hour >= 20) else 0
        is_error = 1 if (status_norm != "SUCCESS" or error_code_norm is not None) else 0
        is_ext_ip = 0 if is_corporate_ip(source_ip) else 1
        is_atyp_reg = 0 if aws_region in EXPECTED_REGIONS else 1
        mfa_disabled = 0 if mfa_auth else 1
        cat_code = CATEGORY_ENCODING.get(category, CATEGORY_ENCODING["UNKNOWN"])

        return cls(
            event_id=str(raw["event_id"]).strip(),
            timestamp=ts,
            timestamp_iso=ts.isoformat(),
            event_name=str(raw["event_name"]).strip(),
            event_source=str(raw["event_source"]).strip(),
            event_category=category,
            user_name=user_name,
            user_type=user_type,
            user_role=user_role,
            user_arn=user_arn,
            mfa_authenticated=mfa_auth,
            source_ip=source_ip,
            aws_region=aws_region,
            status=status_norm,
            error_code=error_code_norm,
            request_count=req_count,
            bytes_transferred=bytes_trans,
            latency_ms=latency,
            user_agent=str(raw.get("user_agent") or "unknown"),
            resource_arn=str(raw.get("resource_arn") or ""),
            raw_metadata=dict(raw.get("metadata") or {}),
            hour_of_day=hour,
            day_of_week=dow,
            is_off_hours=is_off_hours,
            is_error=is_error,
            is_external_ip=is_ext_ip,
            is_atypical_region=is_atyp_reg,
            mfa_disabled_flag=mfa_disabled,
            category_code=cat_code,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Retorna dicionário serializável do registro canônico LGMS."""
        data = asdict(self)
        data["timestamp"] = self.timestamp_iso
        return data


def iter_jsonl_logs(file_path: str | Path) -> Iterator[LGMSRecord]:
    """Lê um arquivo JSONL em streaming e converte linhas válidas em objetos LGMSRecord.

    Linhas em branco, corrompidas ou malformadas geram warning e são ignoradas com segurança.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de logs não encontrado: {path}")

    with path.open("r", encoding="utf-8") as fh:
        for line_num, raw_line in enumerate(fh, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
                yield LGMSRecord.from_raw_dict(payload)
            except (json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
                logger.warning("Linha %d malformada ignorada em %s: %s", line_num, path.name, exc)


def parse_jsonl_logs(
    file_path: str | Path,
    window_minutes: int = 60,
) -> Tuple[List[LGMSRecord], int]:
    """Carrega um lote de logs JSONL, enriquece frequências temporais por janela e retorna (registros, erros)."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de logs não encontrado: {path}")

    records: List[LGMSRecord] = []
    skipped_lines = 0

    with path.open("r", encoding="utf-8") as fh:
        for line_num, raw_line in enumerate(fh, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
                records.append(LGMSRecord.from_raw_dict(payload))
            except (json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
                skipped_lines += 1
                logger.warning("Linha %d inválida ignorada em %s: %s", line_num, path.name, exc)

    enrich_window_frequencies(records, window_minutes=window_minutes)
    return records, skipped_lines


def enrich_window_frequencies(records: List[LGMSRecord], window_minutes: int = 60) -> None:
    """Calcula a frequência de eventos por IP e por usuário dentro de janelas de tempo."""
    if not records:
        return

    bucket_seconds = max(60, window_minutes * 60)
    ip_bucket_counter: Counter[Tuple[str, int]] = Counter()
    user_bucket_counter: Counter[Tuple[str, int]] = Counter()

    for rec in records:
        bucket = int(rec.timestamp.timestamp()) // bucket_seconds
        ip_bucket_counter[(rec.source_ip, bucket)] += rec.request_count
        user_bucket_counter[(rec.user_name, bucket)] += rec.request_count

    for rec in records:
        bucket = int(rec.timestamp.timestamp()) // bucket_seconds
        rec.ip_window_frequency = ip_bucket_counter[(rec.source_ip, bucket)]
        rec.user_window_frequency = user_bucket_counter[(rec.user_name, bucket)]


FEATURE_COLUMNS: List[str] = [
    "request_count",
    "bytes_transferred",
    "log_bytes_transferred",
    "latency_ms",
    "hour_of_day",
    "hour_sin",
    "hour_cos",
    "day_of_week",
    "is_off_hours",
    "is_error",
    "is_external_ip",
    "is_atypical_region",
    "mfa_disabled_flag",
    "category_code",
    "ip_window_frequency",
    "user_window_frequency",
]


def extract_feature_dicts(records: Iterable[LGMSRecord]) -> List[Dict[str, float]]:
    """Extrai dicionários de features numéricas prontos para consumo estatístico e de ML."""
    rows: List[Dict[str, float]] = []
    for rec in records:
        angle = 2.0 * math.pi * (rec.hour_of_day / 24.0)
        rows.append(
            {
                "request_count": float(rec.request_count),
                "bytes_transferred": float(rec.bytes_transferred),
                "log_bytes_transferred": math.log1p(max(0.0, float(rec.bytes_transferred))),
                "latency_ms": float(rec.latency_ms),
                "hour_of_day": float(rec.hour_of_day),
                "hour_sin": round(math.sin(angle), 6),
                "hour_cos": round(math.cos(angle), 6),
                "day_of_week": float(rec.day_of_week),
                "is_off_hours": float(rec.is_off_hours),
                "is_error": float(rec.is_error),
                "is_external_ip": float(rec.is_external_ip),
                "is_atypical_region": float(rec.is_atypical_region),
                "mfa_disabled_flag": float(rec.mfa_disabled_flag),
                "category_code": float(rec.category_code),
                "ip_window_frequency": float(rec.ip_window_frequency),
                "user_window_frequency": float(rec.user_window_frequency),
            }
        )
    return rows


def extract_feature_matrix(records: Iterable[LGMSRecord]) -> Tuple[List[List[float]], List[str]]:
    """Retorna matriz numérica 2D (lista de listas / compatível com NumPy/Scikit-Learn) e nomes das colunas."""
    dicts = extract_feature_dicts(records)
    matrix = [[row[col] for col in FEATURE_COLUMNS] for row in dicts]
    return matrix, list(FEATURE_COLUMNS)


def to_dataframe(records: Iterable[LGMSRecord]):
    """Exporta um pandas.DataFrame com as features extraídas (ou levanta ImportError amigável)."""
    import pandas as pd

    dicts = extract_feature_dicts(records)
    return pd.DataFrame(dicts, columns=FEATURE_COLUMNS)
