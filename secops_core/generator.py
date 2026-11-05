"""Gerador de logs sintéticos realistas estilo AWS CloudTrail em formato JSONL (SEC-02).

Projetado para refletir distribuições estatísticas reais de tráfego de infraestrutura
e segurança (média, desvio padrão, assimetria temporal e correlação multivariada),
permitindo validação rigorosa dos detectores Z-Score, Isolation Forest e Regras CloudTrail.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EventProfile:
    """Perfil estatístico de um evento CloudTrail normal."""

    event_name: str
    event_source: str
    category: str
    weight: float
    req_mean: float
    req_std: float
    bytes_mean: float
    bytes_std: float
    latency_mean: float
    latency_std: float
    error_probability: float = 0.015


NORMAL_EVENT_PROFILES: List[EventProfile] = [
    EventProfile(
        event_name="GetObject",
        event_source="s3.amazonaws.com",
        category="READ",
        weight=0.28,
        req_mean=8.5,
        req_std=3.1,
        bytes_mean=48_500.0,
        bytes_std=14_200.0,
        latency_mean=72.0,
        latency_std=19.5,
        error_probability=0.01,
    ),
    EventProfile(
        event_name="PutObject",
        event_source="s3.amazonaws.com",
        category="WRITE",
        weight=0.14,
        req_mean=5.2,
        req_std=2.0,
        bytes_mean=64_000.0,
        bytes_std=18_500.0,
        latency_mean=95.0,
        latency_std=24.0,
        error_probability=0.01,
    ),
    EventProfile(
        event_name="ListBuckets",
        event_source="s3.amazonaws.com",
        category="READ",
        weight=0.12,
        req_mean=3.0,
        req_std=1.2,
        bytes_mean=2_400.0,
        bytes_std=650.0,
        latency_mean=48.0,
        latency_std=12.0,
        error_probability=0.005,
    ),
    EventProfile(
        event_name="DescribeInstances",
        event_source="ec2.amazonaws.com",
        category="READ",
        weight=0.18,
        req_mean=6.0,
        req_std=2.3,
        bytes_mean=8_200.0,
        bytes_std=2_100.0,
        latency_mean=64.0,
        latency_std=16.0,
        error_probability=0.01,
    ),
    EventProfile(
        event_name="ConsoleLogin",
        event_source="signin.amazonaws.com",
        category="AUTH",
        weight=0.10,
        req_mean=1.4,
        req_std=0.6,
        bytes_mean=1_850.0,
        bytes_std=420.0,
        latency_mean=115.0,
        latency_std=28.0,
        error_probability=0.03,
    ),
    EventProfile(
        event_name="AssumeRole",
        event_source="sts.amazonaws.com",
        category="AUTH",
        weight=0.12,
        req_mean=4.5,
        req_std=1.8,
        bytes_mean=3_100.0,
        bytes_std=780.0,
        latency_mean=54.0,
        latency_std=14.0,
        error_probability=0.01,
    ),
    EventProfile(
        event_name="GetCallerIdentity",
        event_source="sts.amazonaws.com",
        category="READ",
        weight=0.06,
        req_mean=3.8,
        req_std=1.5,
        bytes_mean=1_200.0,
        bytes_std=310.0,
        latency_mean=38.0,
        latency_std=9.5,
        error_probability=0.005,
    ),
]

LEGITIMATE_USERS: List[Dict[str, str]] = [
    {"user_name": "ana.silva", "user_type": "IAMUser", "role": "DataEngineer", "arn": "arn:aws:iam::123456789012:user/ana.silva"},
    {"user_name": "carlos.mendes", "user_type": "IAMUser", "role": "BackendDev", "arn": "arn:aws:iam::123456789012:user/carlos.mendes"},
    {"user_name": "marina.costa", "user_type": "AssumedRole", "role": "SecOpsAnalyst", "arn": "arn:aws:sts::123456789012:assumed-role/SecOpsRole/marina.costa"},
    {"user_name": "rafael.souza", "user_type": "IAMUser", "role": "DevOpsLead", "arn": "arn:aws:iam::123456789012:user/rafael.souza"},
    {"user_name": "bianca.oliveira", "user_type": "AssumedRole", "role": "AppService", "arn": "arn:aws:sts::123456789012:assumed-role/BackendServiceRole/bianca.oliveira"},
    {"user_name": "lucas.ferreira", "user_type": "IAMUser", "role": "CloudArchitect", "arn": "arn:aws:iam::123456789012:user/lucas.ferreira"},
]

CORPORATE_IPS: List[str] = [
    "10.24.12.15",
    "10.24.12.42",
    "10.24.18.103",
    "172.16.8.21",
    "172.16.8.55",
    "192.168.100.14",
    "200.160.2.88",   # Gateway corporativo BR
    "200.160.2.89",
]

SUSPICIOUS_EXTERNAL_IPS: List[str] = [
    "185.220.101.45",  # Tor Exit Node conhecido
    "45.155.205.109",  # Scanner / Brute-force botnet
    "91.240.118.172",  # Infraestrutura C2 externa
    "198.51.100.244",  # Proxy anônimo externo
    "203.0.113.195",   # Host externo não catalogado
    "103.145.13.88",   # Origem geográfica atípica
]

NORMAL_REGIONS: List[str] = ["sa-east-1", "us-east-1"]
ATYPICAL_REGIONS: List[str] = ["ap-northeast-1", "eu-central-1", "ap-southeast-1", "us-west-2"]

NORMAL_USER_AGENTS: List[str] = [
    "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0-105-generic",
    "Boto3/1.34.69 Python/3.11.8 Windows/11",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
    "aws-sdk-go/1.51.6 (go1.22.1; linux; amd64)",
]

SUSPICIOUS_USER_AGENTS: List[str] = [
    "kali-linux/pacu-aws-exploitation-framework/1.5.2",
    "python-requests/2.31.0 (unverified-scanner)",
    "curl/8.4.0",
    "aws-cli/1.18.0 Python/3.8.2 Linux/4.19.0-kali",
]


def _truncated_gauss(
    rng: random.Random,
    mean: float,
    std: float,
    min_val: float,
    max_val: Optional[float] = None,
) -> float:
    """Amostra de uma distribuição normal truncada mantendo média e desvio padrão realistas."""
    for _ in range(12):
        val = rng.gauss(mean, std)
        if val >= min_val and (max_val is None or val <= max_val):
            return val
    clamped = max(min_val, rng.gauss(mean, std))
    if max_val is not None:
        clamped = min(max_val, clamped)
    return clamped


def _generate_business_timestamp(rng: random.Random, base_date: datetime, day_offset: int) -> datetime:
    """Gera timestamp concentrado em horário comercial (μ = 13.5h, σ = 2.6h)."""
    target_day = base_date + timedelta(days=day_offset)
    hour_float = _truncated_gauss(rng, mean=13.5, std=2.6, min_val=7.0, max_val=20.5)
    hour = int(hour_float)
    minute = int((hour_float - hour) * 60)
    second = rng.randint(0, 59)
    return target_day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def _generate_offhours_timestamp(rng: random.Random, base_date: datetime, day_offset: int) -> datetime:
    """Gera timestamp em madrugada/horário atípico (00h00 às 05h30 ou 22h30 às 23h59)."""
    target_day = base_date + timedelta(days=day_offset)
    if rng.random() < 0.82:
        hour_float = _truncated_gauss(rng, mean=2.6, std=1.1, min_val=0.0, max_val=5.4)
    else:
        hour_float = _truncated_gauss(rng, mean=23.1, std=0.4, min_val=22.2, max_val=23.95)
    hour = int(hour_float)
    minute = int((hour_float - hour) * 60)
    second = rng.randint(0, 59)
    return target_day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def _build_normal_record(
    rng: random.Random,
    base_date: datetime,
    total_days: int,
) -> Dict[str, Any]:
    """Constrói um evento basal legítimo com variância natural realista."""
    weights = [p.weight for p in NORMAL_EVENT_PROFILES]
    profile = rng.choices(NORMAL_EVENT_PROFILES, weights=weights, k=1)[0]
    user = rng.choice(LEGITIMATE_USERS)
    day_offset = rng.randint(0, total_days - 1)
    ts = _generate_business_timestamp(rng, base_date, day_offset)

    is_transient_error = rng.random() < profile.error_probability
    status = "FAILURE" if is_transient_error else "SUCCESS"
    error_code = rng.choice(["ThrottlingException", "NoSuchKey"]) if is_transient_error else None

    request_count = int(round(_truncated_gauss(rng, profile.req_mean, profile.req_std, min_val=1.0, max_val=22.0)))
    bytes_transferred = int(
        round(_truncated_gauss(rng, profile.bytes_mean, profile.bytes_std, min_val=250.0, max_val=135_000.0))
    )
    latency_ms = round(_truncated_gauss(rng, profile.latency_mean, profile.latency_std, min_val=15.0, max_val=240.0), 2)

    region = rng.choices(NORMAL_REGIONS, weights=[0.78, 0.22], k=1)[0]
    source_ip = rng.choice(CORPORATE_IPS)

    return {
        "timestamp": ts.isoformat(),
        "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "event_name": profile.event_name,
        "event_source": profile.event_source,
        "event_category": profile.category,
        "user_identity": {
            "user_name": user["user_name"],
            "user_type": user["user_type"],
            "role": user["role"],
            "arn": user["arn"],
            "mfa_authenticated": True,
        },
        "source_ip": source_ip,
        "aws_region": region,
        "status": status,
        "error_code": error_code,
        "request_count": request_count,
        "bytes_transferred": bytes_transferred,
        "latency_ms": latency_ms,
        "user_agent": rng.choice(NORMAL_USER_AGENTS),
        "resource_arn": (
            "arn:aws:s3:::maosnatech-corp-logs/app-data"
            if profile.event_source == "s3.amazonaws.com"
            else "arn:aws:ec2:sa-east-1:123456789012:instance/i-0a1b2c3d4e5f6"
        ),
        "metadata": {
            "is_synthetic_anomaly": False,
            "scenario": "NORMAL_BASELINE",
            "expected_detectors": [],
        },
    }


def _build_anomaly_record(
    rng: random.Random,
    base_date: datetime,
    total_days: int,
    scenario_index: int,
) -> Dict[str, Any]:
    """Constrói um dos 6 cenários de anomalia representativos (volumétricos, multivariados e regras)."""
    day_offset = rng.randint(0, total_days - 1)
    ts = _generate_offhours_timestamp(rng, base_date, day_offset)
    source_ip = rng.choice(SUSPICIOUS_EXTERNAL_IPS)
    region = rng.choice(ATYPICAL_REGIONS)
    user_agent = rng.choice(SUSPICIOUS_USER_AGENTS)
    compromised_user = rng.choice(LEGITIMATE_USERS)

    scenario_type = scenario_index % 6

    if scenario_type == 0:
        # Cenário 1: Brute Force Console Login (Volumétrico + Regra + Multivariado)
        # Alto request_count com desvio padrão realista de rajadas de botnet (μ=68, σ=16)
        req_count = int(round(_truncated_gauss(rng, mean=68.0, std=16.0, min_val=35.0, max_val=130.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=14_500.0, std=4_200.0, min_val=4_500.0)))
        latency = round(_truncated_gauss(rng, mean=295.0, std=68.0, min_val=140.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": "ConsoleLogin",
            "event_source": "signin.amazonaws.com",
            "event_category": "AUTH",
            "user_identity": {
                "user_name": compromised_user["user_name"],
                "user_type": "IAMUser",
                "role": compromised_user["role"],
                "arn": compromised_user["arn"],
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": "us-east-1",
            "status": "FAILURE",
            "error_code": "FailedAuthentication",
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:iam::123456789012:console",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_01_BRUTE_FORCE_CONSOLE",
                "expected_detectors": ["ZSCORE", "ISOLATION_FOREST", "RULE_BRUTE_FORCE_CONSOLE"],
            },
        }

    if scenario_type == 1:
        # Cenário 2: Exfiltração Massiva S3 + Rajada de Leitura (Alto Z-Score em bytes e requests + Isolation Forest)
        # Bytes na casa de múltiplos megabytes com dispersão elevada (μ=2_450_000 B, σ=680_000 B)
        req_count = int(round(_truncated_gauss(rng, mean=84.0, std=21.0, min_val=42.0, max_val=160.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=2_450_000.0, std=680_000.0, min_val=950_000.0)))
        latency = round(_truncated_gauss(rng, mean=440.0, std=110.0, min_val=210.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": "GetObject",
            "event_source": "s3.amazonaws.com",
            "event_category": "READ",
            "user_identity": {
                "user_name": compromised_user["user_name"],
                "user_type": compromised_user["user_type"],
                "role": compromised_user["role"],
                "arn": compromised_user["arn"],
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": region,
            "status": "SUCCESS",
            "error_code": None,
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:s3:::maosnatech-clientes-pii-prod/exports/full_dump.parquet",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_02_S3_MASS_EXFILTRATION",
                "expected_detectors": ["ZSCORE", "ISOLATION_FOREST"],
            },
        }

    if scenario_type == 2:
        # Cenário 3: Escalação de Privilégio IAM Furtiva (Baixo volume, pega por Regra CloudTrail + Isolation Forest)
        event_name = rng.choice(["PutUserPolicy", "AttachUserPolicy", "CreateAccessKey", "AddUserToGroup"])
        req_count = int(round(_truncated_gauss(rng, mean=2.8, std=1.1, min_val=1.0, max_val=6.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=4_200.0, std=950.0, min_val=1_500.0)))
        latency = round(_truncated_gauss(rng, mean=165.0, std=35.0, min_val=85.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": event_name,
            "event_source": "iam.amazonaws.com",
            "event_category": "ADMIN",
            "user_identity": {
                "user_name": compromised_user["user_name"],
                "user_type": "IAMUser",
                "role": compromised_user["role"],
                "arn": compromised_user["arn"],
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": "us-east-1",
            "status": "SUCCESS",
            "error_code": None,
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:iam::123456789012:policy/AdministratorAccess",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_03_IAM_PRIVILEGE_ESCALATION",
                "expected_detectors": ["RULE_IAM_PRIVILEGE_ESCALATION", "ISOLATION_FOREST"],
            },
        }

    if scenario_type == 3:
        # Cenário 4: Sabotagem de Auditoria CloudTrail (DeleteTrail / StopLogging)
        event_name = rng.choice(["StopLogging", "DeleteTrail", "UpdateTrail"])
        req_count = int(round(_truncated_gauss(rng, mean=1.8, std=0.8, min_val=1.0, max_val=4.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=1_950.0, std=480.0, min_val=900.0)))
        latency = round(_truncated_gauss(rng, mean=145.0, std=32.0, min_val=75.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": event_name,
            "event_source": "cloudtrail.amazonaws.com",
            "event_category": "SECURITY_TAMPERING",
            "user_identity": {
                "user_name": compromised_user["user_name"],
                "user_type": "AssumedRole",
                "role": compromised_user["role"],
                "arn": compromised_user["arn"],
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": region,
            "status": "SUCCESS",
            "error_code": None,
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:cloudtrail:sa-east-1:123456789012:trail/organization-audit-trail",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_04_CLOUDTRAIL_TAMPERING",
                "expected_detectors": ["RULE_TRAIL_TAMPERING", "ISOLATION_FOREST"],
            },
        }

    if scenario_type == 4:
        # Cenário 5: Varredura Não Autorizada / Descoberta de Recursos com AccessDenied (Burst)
        event_name = rng.choice(["DescribeSecrets", "ListUsers", "GetBucketAcl", "DescribeDBInstances"])
        event_source_map = {
            "DescribeSecrets": "secretsmanager.amazonaws.com",
            "ListUsers": "iam.amazonaws.com",
            "GetBucketAcl": "s3.amazonaws.com",
            "DescribeDBInstances": "rds.amazonaws.com",
        }
        req_count = int(round(_truncated_gauss(rng, mean=58.0, std=15.0, min_val=30.0, max_val=110.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=28_000.0, std=7_500.0, min_val=9_000.0)))
        latency = round(_truncated_gauss(rng, mean=330.0, std=75.0, min_val=160.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": event_name,
            "event_source": event_source_map[event_name],
            "event_category": "DISCOVERY",
            "user_identity": {
                "user_name": compromised_user["user_name"],
                "user_type": compromised_user["user_type"],
                "role": compromised_user["role"],
                "arn": compromised_user["arn"],
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": region,
            "status": "FAILURE",
            "error_code": rng.choice(["AccessDenied", "UnauthorizedOperation"]),
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:secretsmanager:sa-east-1:123456789012:secret:prod/db/master",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_05_UNAUTHORIZED_API_BURST",
                "expected_detectors": ["ZSCORE", "ISOLATION_FOREST", "RULE_UNAUTHORIZED_API_BURST"],
            },
        }

    # Cenário 6: Uso de Conta Root ou Exposição Pública de Bucket S3 Crítico
    use_root_variant = (scenario_index // 6) % 2 == 0
    if use_root_variant:
        req_count = int(round(_truncated_gauss(rng, mean=3.2, std=1.2, min_val=1.0, max_val=7.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=6_400.0, std=1_600.0, min_val=2_000.0)))
        latency = round(_truncated_gauss(rng, mean=180.0, std=42.0, min_val=90.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": "CreateAccessKey",
            "event_source": "iam.amazonaws.com",
            "event_category": "ADMIN",
            "user_identity": {
                "user_name": "root",
                "user_type": "Root",
                "role": "AccountRoot",
                "arn": "arn:aws:iam::123456789012:root",
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": "us-east-1",
            "status": "SUCCESS",
            "error_code": None,
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:iam::123456789012:root",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_06A_ROOT_ACCOUNT_ACTIVITY",
                "expected_detectors": ["RULE_ROOT_ACTIVITY", "ISOLATION_FOREST"],
            },
        }
    else:
        req_count = int(round(_truncated_gauss(rng, mean=2.5, std=1.0, min_val=1.0, max_val=6.0)))
        bytes_trans = int(round(_truncated_gauss(rng, mean=5_100.0, std=1_100.0, min_val=2_200.0)))
        latency = round(_truncated_gauss(rng, mean=155.0, std=36.0, min_val=80.0), 2)
        return {
            "timestamp": ts.isoformat(),
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "event_name": rng.choice(["PutBucketAcl", "PutBucketPolicy", "DeletePublicAccessBlock"]),
            "event_source": "s3.amazonaws.com",
            "event_category": "POLICY_CHANGE",
            "user_identity": {
                "user_name": compromised_user["user_name"],
                "user_type": "IAMUser",
                "role": compromised_user["role"],
                "arn": compromised_user["arn"],
                "mfa_authenticated": False,
            },
            "source_ip": source_ip,
            "aws_region": region,
            "status": "SUCCESS",
            "error_code": None,
            "request_count": req_count,
            "bytes_transferred": bytes_trans,
            "latency_ms": latency,
            "user_agent": user_agent,
            "resource_arn": "arn:aws:s3:::maosnatech-financeiro-confidencial",
            "metadata": {
                "is_synthetic_anomaly": True,
                "scenario": "SCENARIO_06B_SENSITIVE_S3_PUBLIC_ACCESS",
                "expected_detectors": ["RULE_SENSITIVE_S3_PUBLIC_ACCESS", "ISOLATION_FOREST"],
            },
        }


def generate_synthetic_logs(
    output_path: str | Path = "data/logs_simulados.jsonl",
    total_records: int = 1500,
    anomaly_rate: float = 0.06,
    seed: int = 42,
    mirror_root_jsonl: bool = True,
) -> Dict[str, Any]:
    """Gera o arquivo JSONL de logs sintéticos e retorna estatísticas de validação."""
    if total_records <= 0:
        raise ValueError("total_records deve ser maior que zero.")
    if not (0.0 <= anomaly_rate < 1.0):
        raise ValueError("anomaly_rate deve estar entre 0.0 e 1.0.")

    rng = random.Random(seed)
    num_anomalies = int(round(total_records * anomaly_rate))
    num_normals = total_records - num_anomalies

    base_date = datetime(2026, 10, 26, 0, 0, 0, tzinfo=timezone(timedelta(hours=-3)))
    total_days = 7

    records: List[Dict[str, Any]] = []
    for _ in range(num_normals):
        records.append(_build_normal_record(rng, base_date, total_days))

    for idx in range(num_anomalies):
        records.append(_build_anomaly_record(rng, base_date, total_days, idx))

    # Ordena cronologicamente para simular um stream contínuo real de CloudTrail
    records.sort(key=lambda r: r["timestamp"])

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Mantém cópia sincronizada na raiz caso scripts/usuário referenciem logs_simulados.jsonl direto
    if mirror_root_jsonl:
        root_file = Path("logs_simulados.jsonl")
        if root_file.resolve() != out_file.resolve():
            with root_file.open("w", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return compute_dataset_statistics(records, str(out_file))


def _mean_and_std(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    n = len(values)
    mean_val = sum(values) / n
    variance = sum((x - mean_val) ** 2 for x in values) / max(1, n - 1)
    return {
        "mean": round(mean_val, 2),
        "std": round(math.sqrt(variance), 2),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
    }


def compute_dataset_statistics(records: List[Dict[str, Any]], output_path: str) -> Dict[str, Any]:
    """Calcula média e desvio padrão separados para logs normais, anormais (geral e volumétricos)."""
    normals = [r for r in records if not r["metadata"]["is_synthetic_anomaly"]]
    anomalies = [r for r in records if r["metadata"]["is_synthetic_anomaly"]]
    volumetric_anomalies = [
        r for r in anomalies if "ZSCORE" in r["metadata"]["expected_detectors"]
    ]
    stealth_anomalies = [
        r for r in anomalies if "ZSCORE" not in r["metadata"]["expected_detectors"]
    ]

    scenario_counts: Dict[str, int] = {}
    for r in anomalies:
        sc = r["metadata"]["scenario"]
        scenario_counts[sc] = scenario_counts.get(sc, 0) + 1

    return {
        "output_path": output_path,
        "total_records": len(records),
        "normal_records": len(normals),
        "anomaly_records": len(anomalies),
        "anomaly_rate_actual": round(len(anomalies) / max(1, len(records)), 4),
        "stats_normal": {
            "request_count": _mean_and_std([float(r["request_count"]) for r in normals]),
            "bytes_transferred": _mean_and_std([float(r["bytes_transferred"]) for r in normals]),
            "latency_ms": _mean_and_std([float(r["latency_ms"]) for r in normals]),
        },
        "stats_anomaly_all": {
            "request_count": _mean_and_std([float(r["request_count"]) for r in anomalies]),
            "bytes_transferred": _mean_and_std([float(r["bytes_transferred"]) for r in anomalies]),
            "latency_ms": _mean_and_std([float(r["latency_ms"]) for r in anomalies]),
        },
        "stats_anomaly_volumetric": {
            "request_count": _mean_and_std([float(r["request_count"]) for r in volumetric_anomalies]),
            "bytes_transferred": _mean_and_std([float(r["bytes_transferred"]) for r in volumetric_anomalies]),
            "latency_ms": _mean_and_std([float(r["latency_ms"]) for r in volumetric_anomalies]),
        },
        "stats_anomaly_stealth": {
            "request_count": _mean_and_std([float(r["request_count"]) for r in stealth_anomalies]),
            "bytes_transferred": _mean_and_std([float(r["bytes_transferred"]) for r in stealth_anomalies]),
            "latency_ms": _mean_and_std([float(r["latency_ms"]) for r in stealth_anomalies]),
        },
        "scenario_breakdown": scenario_counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gerador de logs sintéticos CloudTrail em formato JSONL (secops_core)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/logs_simulados.jsonl",
        help="Caminho do arquivo JSONL gerado (default: data/logs_simulados.jsonl)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1500,
        help="Quantidade total de eventos gerados (default: 1500)",
    )
    parser.add_argument(
        "--anomaly-rate",
        type=float,
        default=0.06,
        help="Proporção de anomalias injetadas entre 0.0 e 1.0 (default: 0.06)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Semente aleatória para reprodutibilidade (default: 42)",
    )
    args = parser.parse_args()

    stats = generate_synthetic_logs(
        output_path=args.output,
        total_records=args.count,
        anomaly_rate=args.anomaly_rate,
        seed=args.seed,
    )
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
