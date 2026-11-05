"""Testes automatizados para os endpoints REST da FastAPI (SEC-11, SEC-12, SEC-15)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app


def test_fastapi_endpoints_end_to_end(tmp_path: Path, monkeypatch) -> None:
    test_db = tmp_path / "api_test.db"
    test_logs = tmp_path / "api_logs.jsonl"
    monkeypatch.setenv("SQLITE_DB_PATH", str(test_db))
    monkeypatch.setenv("LOGS_JSONL_PATH", str(test_logs))

    client = TestClient(app)

    # 1. Dispara o pipeline via POST /pipeline/run
    run_resp = client.post(
        "/pipeline/run",
        json={
            "regenerate_logs": True,
            "total_records": 150,
            "anomaly_rate": 0.08,
            "seed": 42,
            "generate_explanations": True,
        },
    )
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert run_data["records_processed"] == 150
    assert run_data["anomalies_detected"] > 0

    # 2. Consulta /health
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["total_logs_in_db"] == 150

    # 3. Consulta /stats
    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert stats_data["total_logs"] == 150
    assert stats_data["total_anomalies"] == run_data["anomalies_detected"]

    # 4. Consulta /logs filtrado por is_anomaly=true
    logs_resp = client.get("/logs", params={"is_anomaly": True, "limit": 20})
    assert logs_resp.status_code == 200
    items = logs_resp.json()["items"]
    assert len(items) > 0
    first_event_id = items[0]["event_id"]

    # 5. Consulta detalhe de uma anomalia GET /anomalies/{event_id}
    detail_resp = client.get(f"/anomalies/{first_event_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["event_id"] == first_event_id

    # 6. Gera explicação sob demanda POST /anomalies/{event_id}/explain
    exp_resp = client.post(f"/anomalies/{first_event_id}/explain")
    assert exp_resp.status_code == 200
    assert "O que aconteceu" in exp_resp.json()["ai_explanation"]

    # 7. Evento inexistente retorna 404
    not_found = client.get("/anomalies/non-existent-id-999")
    assert not_found.status_code == 404
