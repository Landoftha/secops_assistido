"""Testes automatizados para os detectores Z-Score, Isolation Forest e Regras CloudTrail (SEC-05, SEC-06, SEC-07, SEC-15)."""

from __future__ import annotations

from pathlib import Path

from secops_core.detectors.cloudtrail_rules import CloudTrailRuleEngine
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.zscore_detector import ZScoreDetector
from secops_core.generator import generate_synthetic_logs
from secops_core.lgms import LGMSRecord, parse_jsonl_logs


def _make_record(**overrides) -> LGMSRecord:
    base = {
        "timestamp": "2026-10-27T14:00:00-03:00",
        "event_id": "evt-001",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "event_category": "READ",
        "user_identity": {
            "user_name": "ana.silva",
            "user_type": "IAMUser",
            "role": "DataEngineer",
            "arn": "arn:aws:iam::123456789012:user/ana.silva",
            "mfa_authenticated": True,
        },
        "source_ip": "10.24.12.15",
        "aws_region": "sa-east-1",
        "status": "SUCCESS",
        "error_code": None,
        "request_count": 5,
        "bytes_transferred": 20000,
        "latency_ms": 65.0,
        "user_agent": "aws-cli/2.15",
        "resource_arn": "arn:aws:s3:::corp-bucket/file.csv",
    }
    base.update(overrides)
    return LGMSRecord.from_raw_dict(base)


def test_zscore_zero_std_and_extreme_outlier() -> None:
    constant_records = [_make_record(event_id=f"c-{i}", request_count=5, bytes_transferred=1000, latency_ms=50.0) for i in range(25)]
    detector = ZScoreDetector(threshold=3.0)
    res_const = detector.fit_predict(constant_records)
    assert all(r.zscore_value == 0.0 and not r.is_zscore_anomaly for r in res_const)

    # Adiciona 1 pico extremo
    spike = _make_record(event_id="spike-1", request_count=120, bytes_transferred=2_500_000, latency_ms=420.0)
    res_spike = detector.fit_predict(constant_records + [spike])
    spike_result = next(r for r in res_spike if r.event_id == "spike-1")
    assert spike_result.is_zscore_anomaly is True
    assert spike_result.zscore_value > 3.0


def test_isolation_forest_reproducibility_and_anomaly_scoring(tmp_path: Path) -> None:
    out_file = tmp_path / "iforest_logs.jsonl"
    generate_synthetic_logs(output_path=out_file, total_records=250, anomaly_rate=0.06, seed=42, mirror_root_jsonl=False)
    records, _ = parse_jsonl_logs(out_file)

    det1 = IsolationForestDetector(contamination=0.06, random_state=42)
    det2 = IsolationForestDetector(contamination=0.06, random_state=42)
    r1 = det1.fit_predict(records)
    r2 = det2.fit_predict(records)

    assert [x.iforest_score for x in r1] == [x.iforest_score for x in r2]

    normal_scores = [res.iforest_score for rec, res in zip(records, r1) if not rec.raw_metadata.get("is_synthetic_anomaly")]
    anom_scores = [res.iforest_score for rec, res in zip(records, r1) if rec.raw_metadata.get("is_synthetic_anomaly")]
    assert sum(anom_scores) / len(anom_scores) < sum(normal_scores) / len(normal_scores)


def test_cloudtrail_all_six_rules() -> None:
    engine = CloudTrailRuleEngine()

    # 1. IAM Privilege Escalation
    r_iam = _make_record(event_name="PutUserPolicy", event_source="iam.amazonaws.com")
    assert any(m.rule_code == "RULE_IAM_PRIVILEGE_ESCALATION" for m in engine.evaluate_record(r_iam))

    # 2. Trail Tampering
    r_trail = _make_record(event_name="StopLogging", event_source="cloudtrail.amazonaws.com")
    assert any(m.rule_code == "RULE_TRAIL_TAMPERING" for m in engine.evaluate_record(r_trail))

    # 3. Root Activity
    r_root = _make_record(
        event_name="CreateAccessKey",
        user_identity={"user_name": "root", "user_type": "Root", "role": "AccountRoot", "mfa_authenticated": False},
    )
    assert any(m.rule_code == "RULE_ROOT_ACTIVITY" for m in engine.evaluate_record(r_root))

    # 4. Brute Force Console
    r_bf = _make_record(event_name="ConsoleLogin", status="FAILURE", error_code="FailedAuthentication", request_count=45)
    assert any(m.rule_code == "RULE_BRUTE_FORCE_CONSOLE" for m in engine.evaluate_record(r_bf))

    # 5. Unauthorized API Burst
    r_unauth = _make_record(event_name="DescribeSecrets", status="FAILURE", error_code="AccessDenied", request_count=35)
    assert any(m.rule_code == "RULE_UNAUTHORIZED_API_BURST" for m in engine.evaluate_record(r_unauth))

    # 6. Sensitive S3 Public Access
    r_s3 = _make_record(event_name="PutBucketAcl", event_source="s3.amazonaws.com")
    assert any(m.rule_code == "RULE_SENSITIVE_S3_PUBLIC_ACCESS" for m in engine.evaluate_record(r_s3))

    # Evento normal não dispara nenhuma regra
    r_ok = _make_record()
    assert engine.evaluate_record(r_ok) == []
