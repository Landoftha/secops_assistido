"""Testes do pipeline ponta a ponta e regressões dos critérios de aceite do Linear (MAO-6 a MAO-23)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from secops_core.config import get_settings
from secops_core.db import SecOpsDatabase
from secops_core.detectors.zscore_detector import ZScoreDetector
from secops_core.explainer.prompt_builder import render_alert_prompt, render_fallback_explanation
from secops_core.generator import generate_synthetic_logs
from secops_core.pipeline import run_detection_pipeline
from tests.test_detectors import _make_record
from tests.test_explainer_and_db import _sample_alert_dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# --- MAO-6: configuração via variáveis de ambiente --------------------------------------


def test_settings_are_read_from_environment_at_call_time(monkeypatch) -> None:
    monkeypatch.setenv("ZSCORE_THRESHOLD", "4.5")
    monkeypatch.setenv("SQLITE_DB_PATH", "custom/dir/x.db")
    settings = get_settings()
    assert settings.zscore_threshold == 4.5
    assert settings.sqlite_db_path == Path("custom/dir/x.db")


# --- MAO-23: testes não podem sobrescrever os dados de demonstração ---------------------


def test_generator_does_not_touch_demo_files_by_default(tmp_path: Path) -> None:
    demo_files = [PROJECT_ROOT / "logs_simulados.jsonl", PROJECT_ROOT / "data" / "logs_simulados.jsonl"]
    before = {p: p.stat().st_mtime_ns for p in demo_files if p.exists()}

    generate_synthetic_logs(output_path=tmp_path / "x.jsonl", total_records=60, seed=1)

    after = {p: p.stat().st_mtime_ns for p in demo_files if p.exists()}
    assert before == after


# --- MAO-14: pipeline ponta a ponta -----------------------------------------------------


def test_pipeline_detects_all_injected_scenarios(tmp_path: Path) -> None:
    logs = tmp_path / "logs.jsonl"
    db_file = tmp_path / "p.db"
    result = run_detection_pipeline(
        logs_path=logs, db_path=db_file, regenerate_logs=True, total_records=600, seed=42
    )
    assert result["status"] == "success"
    assert result["records_processed"] == 600

    db = SecOpsDatabase(db_file)
    rows = db.query_logs(limit=1000)
    injected = [r for r in rows if r["raw_metadata"].get("is_synthetic_anomaly")]
    assert injected, "o gerador deveria injetar anomalias"
    # Toda anomalia injetada precisa ser sinalizada por pelo menos um detector (recall 100%)
    assert all(r["is_anomaly"] for r in injected)
    # E a severidade consolidada precisa ser coerente com a presença de regras CRITICAL
    for r in rows:
        if any(rule["severity"] == "CRITICAL" for rule in r["cloudtrail_rules_triggered"]):
            assert r["final_severity"] == "CRITICAL"


def test_pipeline_regeneration_replaces_dataset_and_reports_run_counts(tmp_path: Path) -> None:
    logs = tmp_path / "logs.jsonl"
    db_file = tmp_path / "p.db"
    run_detection_pipeline(logs_path=logs, db_path=db_file, regenerate_logs=True, total_records=500, seed=1)

    second = run_detection_pipeline(
        logs_path=logs, db_path=db_file, regenerate_logs=True, total_records=200, seed=2
    )
    stats = SecOpsDatabase(db_file).get_summary_stats()
    # O banco reflete apenas o dataset atual (sem "sobras" da execução anterior)
    assert stats["total_logs"] == 200
    assert second["anomalies_detected"] == stats["total_anomalies"]
    assert second["by_severity"] == stats["by_severity"]


def test_pipeline_reuses_explanations_and_limits_new_ones(tmp_path: Path) -> None:
    logs = tmp_path / "logs.jsonl"
    db_file = tmp_path / "p.db"
    first = run_detection_pipeline(
        logs_path=logs,
        db_path=db_file,
        regenerate_logs=True,
        total_records=400,
        seed=3,
        generate_explanations=True,
        max_explanations=5,
    )
    assert first["explanations_generated"] == 5

    # Reprocessar sem explicações não apaga as já existentes
    run_detection_pipeline(logs_path=logs, db_path=db_file)
    db = SecOpsDatabase(db_file)
    explained = [r for r in db.query_logs(is_anomaly=True, limit=1000) if r["ai_explanation"]]
    assert len(explained) == 5
    # As primeiras explicações vão para os alertas mais graves
    assert all(r["final_severity"] == "CRITICAL" for r in explained)

    # Nova execução gera apenas as que faltam
    third = run_detection_pipeline(
        logs_path=logs, db_path=db_file, generate_explanations=True, max_explanations=1000
    )
    assert third["explanations_generated"] == third["anomalies_detected"] - 5


def test_pipeline_with_empty_logs_returns_full_summary(tmp_path: Path, monkeypatch) -> None:
    logs = tmp_path / "empty.jsonl"
    logs.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "e.db"))
    monkeypatch.setenv("LOGS_JSONL_PATH", str(logs))

    resp = TestClient(app).post("/pipeline/run", json={"generate_explanations": False})
    assert resp.status_code == 200
    assert resp.json()["status"] == "empty"
    assert resp.json()["records_processed"] == 0


# --- MAO-9: performance SQLite ----------------------------------------------------------


def test_sqlite_filtered_queries_under_100ms_for_5000_records(tmp_path: Path) -> None:
    db = SecOpsDatabase(tmp_path / "perf.db")
    base = _sample_alert_dict()
    rows = []
    for i in range(5000):
        row = dict(base)
        row["event_id"] = f"evt-{i:05d}"
        row["timestamp"] = f"2026-10-{26 + (i % 5):02d}T{i % 24:02d}:00:00-03:00"
        row["is_anomaly"] = i % 10 == 0
        row["final_severity"] = "CRITICAL" if i % 10 == 0 else "LOW"
        rows.append(row)
    db.bulk_upsert_logs(rows)

    for kwargs in (
        {"is_anomaly": True, "limit": 500},
        {"severity": "CRITICAL", "limit": 500},
        {"detector_type": "CLOUDTRAIL", "limit": 500},
    ):
        t0 = time.perf_counter()
        db.query_logs(**kwargs)
        assert (time.perf_counter() - t0) * 1000 < 100, kwargs

    t0 = time.perf_counter()
    db.get_summary_stats()
    assert (time.perf_counter() - t0) * 1000 < 100


# --- MAO-11: Z-Score em distribuição normal ---------------------------------------------


def test_zscore_normal_distribution_has_no_false_positives() -> None:
    values = [8, 9, 10, 11, 12, 9, 10, 11, 10, 10, 9, 11, 10, 12, 8, 10, 11, 9, 10, 10]
    records = [_make_record(event_id=f"n-{i}", request_count=v) for i, v in enumerate(values)]
    results = ZScoreDetector(threshold=3.0).fit_predict(records)
    assert not any(r.is_zscore_anomaly for r in results)


# --- MAO-16: template Jinja2 com combinações de detectores -------------------------------


@pytest.mark.parametrize(
    "zscore,iforest,rules,expected",
    [
        (True, False, [], "Desvio Estatístico"),
        (False, True, [], "Anomalia Multivariada"),
        (False, False, True, "Regra CloudTrail"),
        (True, True, True, "Regra CloudTrail"),
    ],
)
def test_templates_for_each_detector_combination(zscore, iforest, rules, expected) -> None:
    alert = _sample_alert_dict()
    alert["is_zscore_anomaly"] = zscore
    alert["is_iforest_anomaly"] = iforest
    if not rules:
        alert["cloudtrail_rules_triggered"] = []
        alert["is_cloudtrail_anomaly"] = False

    fallback = render_fallback_explanation(alert)
    assert expected in fallback
    for section in ("O que aconteceu", "Por que foi considerado anômalo", "Risco Potencial", "Ação Recomendada"):
        assert section in fallback

    prompt = render_alert_prompt(alert)
    if not rules:
        assert "Nenhuma regra determinística" in prompt


# --- MAO-18: validação e filtros da API -------------------------------------------------


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("LOGS_JSONL_PATH", str(tmp_path / "api_logs.jsonl"))
    client = TestClient(app)
    resp = client.post(
        "/pipeline/run",
        json={"regenerate_logs": True, "total_records": 300, "seed": 5, "generate_explanations": False},
    )
    assert resp.status_code == 200
    return client


def test_api_rejects_invalid_filters_with_422(api_client: TestClient) -> None:
    assert api_client.get("/logs", params={"detector_type": "banana"}).status_code == 422
    assert api_client.get("/logs", params={"severity": "URGENT"}).status_code == 422
    assert api_client.get("/logs", params={"limit": 0}).status_code == 422
    assert api_client.post("/pipeline/run", json={"total_records": 10}).status_code == 422


def test_api_combined_filters(api_client: TestClient) -> None:
    resp = api_client.get(
        "/logs", params={"is_anomaly": True, "severity": "critical", "detector_type": "cloudtrail", "limit": 2000}
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert items
    assert all(i["is_anomaly"] and i["final_severity"] == "CRITICAL" and i["is_cloudtrail_anomaly"] for i in items)

    ip = items[0]["source_ip"]
    by_ip = api_client.get("/logs", params={"source_ip": ip, "limit": 2000}).json()["items"]
    assert by_ip and all(i["source_ip"] == ip for i in by_ip)


def test_api_stats_include_top_users(api_client: TestClient) -> None:
    stats = api_client.get("/stats").json()
    assert stats["top_suspicious_users"]
    assert {"user_name", "count"} <= set(stats["top_suspicious_users"][0])


# --- MAO-21 / MAO-22: dashboard Streamlit -----------------------------------------------


def test_streamlit_dashboard_renders_without_errors(tmp_path: Path, monkeypatch) -> None:
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "dash.db"))
    monkeypatch.setenv("LOGS_JSONL_PATH", str(tmp_path / "dash_logs.jsonl"))
    monkeypatch.setenv("API_BASE_URL", "http://127.0.0.1:9")  # API offline -> modo serviço local
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:9")
    run_detection_pipeline(regenerate_logs=True, total_records=300, seed=7)

    at = AppTest.from_file(str(PROJECT_ROOT / "dashboard" / "app.py"), default_timeout=120)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    labels = [m.label for m in at.metric]
    for expected in ("Total de Logs Analisados", "Total de Anomalias", "% de Anomalias", "Status do Motor IA"):
        assert expected in labels

    # Não expõe caminhos absolutos do sistema na UI
    sidebar_text = " ".join(m.value for m in at.sidebar.markdown)
    assert str(tmp_path) not in sidebar_text

    # Filtro por IP no campo "Usuário/IP"
    first_ip = SecOpsDatabase().query_logs(is_anomaly=True, limit=1)[0]["source_ip"]
    at.text_input[1].input(first_ip).run()
    assert not at.exception, [e.value for e in at.exception]

    # Regenerar explicação
    regen = next(b for b in at.button if "Regenerar" in b.label)
    regen.click().run()
    assert not at.exception, [e.value for e in at.exception]
