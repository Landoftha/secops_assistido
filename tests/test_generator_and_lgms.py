"""Testes automatizados para geração de logs sintéticos JSONL e parser LGMS (SEC-02, SEC-03, SEC-15)."""

from __future__ import annotations

from pathlib import Path

from secops_core.generator import generate_synthetic_logs
from secops_core.lgms import (
    FEATURE_COLUMNS,
    LGMSRecord,
    extract_feature_matrix,
    parse_jsonl_logs,
)


def test_generator_creates_valid_jsonl_and_realistic_std(tmp_path: Path) -> None:
    out_file = tmp_path / "test_logs.jsonl"
    stats = generate_synthetic_logs(
        output_path=out_file,
        total_records=300,
        anomaly_rate=0.06,
        seed=42,
        mirror_root_jsonl=False,
    )
    assert out_file.exists()
    assert stats["total_records"] == 300
    assert stats["anomaly_records"] == 18
    assert stats["normal_records"] == 282
    assert len(stats["scenario_breakdown"]) >= 5

    # Valida que o desvio padrão dos logs normais é controlado e o das anomalias volumétricas é elevado
    normal_req_std = stats["stats_normal"]["request_count"]["std"]
    vol_req_mean = stats["stats_anomaly_volumetric"]["request_count"]["mean"]
    assert 1.5 <= normal_req_std <= 6.0
    assert vol_req_mean > stats["stats_normal"]["request_count"]["mean"] * 5


def test_lgms_parses_all_valid_lines_and_handles_corrupted_lines(tmp_path: Path) -> None:
    out_file = tmp_path / "mixed_logs.jsonl"
    generate_synthetic_logs(
        output_path=out_file,
        total_records=60,
        anomaly_rate=0.10,
        seed=7,
        mirror_root_jsonl=False,
    )
    # Injeta linhas malformadas para testar resiliência do LGMS
    with out_file.open("a", encoding="utf-8") as fh:
        fh.write("{corrupted_json_line\n")
        fh.write('{"timestamp": "2026-10-27T10:00:00-03:00"}\n')

    records, skipped = parse_jsonl_logs(out_file)
    assert len(records) == 60
    assert skipped == 2
    assert all(isinstance(r, LGMSRecord) for r in records)

    matrix, cols = extract_feature_matrix(records)
    assert len(matrix) == 60
    assert cols == FEATURE_COLUMNS
    assert len(matrix[0]) == len(FEATURE_COLUMNS)
