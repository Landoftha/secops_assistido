"""Testes automatizados para templates Jinja2, fallback Ollama e persistência SQLite (SEC-04, SEC-09, SEC-10, SEC-15)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from secops_core.db import SecOpsDatabase
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.explainer.prompt_builder import (
    render_alert_prompt,
    render_fallback_explanation,
)


def _sample_alert_dict(event_id: str = "evt-test-100") -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-10-28T02:15:00-03:00",
        "event_name": "StopLogging",
        "event_source": "cloudtrail.amazonaws.com",
        "event_category": "SECURITY_TAMPERING",
        "user_name": "carlos.mendes",
        "user_type": "AssumedRole",
        "user_role": "BackendDev",
        "user_arn": "arn:aws:iam::123456789012:user/carlos.mendes",
        "mfa_authenticated": False,
        "source_ip": "185.220.101.45",
        "aws_region": "ap-northeast-1",
        "status": "SUCCESS",
        "error_code": None,
        "request_count": 2,
        "bytes_transferred": 1800,
        "latency_ms": 140.0,
        "user_agent": "kali-linux/pacu",
        "resource_arn": "arn:aws:cloudtrail:sa-east-1:123456789012:trail/org-trail",
        "hour_of_day": 2,
        "day_of_week": 2,
        "is_off_hours": 1,
        "is_error": 0,
        "is_external_ip": 1,
        "is_atypical_region": 1,
        "zscore_value": 1.12,
        "is_zscore_anomaly": False,
        "iforest_score": -0.145,
        "is_iforest_anomaly": True,
        "cloudtrail_rules_triggered": [
            {
                "rule_code": "RULE_TRAIL_TAMPERING",
                "rule_name": "Sabotagem de Auditoria CloudTrail",
                "severity": "CRITICAL",
                "reason": "Tentativa de interromper auditoria.",
            }
        ],
        "is_cloudtrail_anomaly": True,
        "final_severity": "CRITICAL",
        "is_anomaly": True,
    }


def test_jinja2_prompt_and_fallback_rendering() -> None:
    alert = _sample_alert_dict()
    prompt = render_alert_prompt(alert)
    assert "StopLogging" in prompt
    assert "RULE_TRAIL_TAMPERING" in prompt
    assert "1) **O que aconteceu (Resumo Simples):**" in prompt

    fallback = render_fallback_explanation(alert)
    assert "O que aconteceu (Resumo Simples)" in fallback
    assert "Por que foi considerado anômalo" in fallback
    assert "Risco Potencial" in fallback
    assert "Ação Recomendada" in fallback


def test_ollama_client_fallback_when_offline_and_mocked_online(tmp_path: Path) -> None:
    db_file = tmp_path / "test_secops.db"
    db = SecOpsDatabase(db_file)
    alert = _sample_alert_dict("evt-db-01")
    db.bulk_upsert_logs([alert])

    # Idempotência ao reinserir o mesmo event_id
    db.bulk_upsert_logs([alert])
    stats = db.get_summary_stats()
    assert stats["total_logs"] == 1
    assert stats["total_anomalies"] == 1

    # Testa modo fallback quando servidor está inacessível
    offline_client = OllamaExplainerClient(base_url="http://127.0.0.1:59999", timeout_seconds=0.3)
    exp_text = offline_client.explain_and_persist("evt-db-01", db=db)
    assert exp_text is not None
    assert "Ação Recomendada" in exp_text

    saved = db.get_by_event_id("evt-db-01")
    assert saved is not None
    assert saved["ai_explanation"] == exp_text

    # Testa com mock simulando Ollama online
    with patch.object(
        OllamaExplainerClient,
        "check_health",
        return_value={"online": True, "mode": "ollama_local"},
    ), patch("httpx.Client.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.raise_for_status = lambda: None
        mock_post.return_value.json = lambda: {"response": "Explicação gerada pelo Ollama Mock!"}

        online_client = OllamaExplainerClient()
        res_online = online_client.explain_alert(alert)
        assert res_online == "Explicação gerada pelo Ollama Mock!"
