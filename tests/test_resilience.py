from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from mspops.api import app
from mspops.resilience import SnapshotPolicy, calculate_resilience

client = TestClient(app)

def test_empty_policies():
    report = calculate_resilience("CLI-000", [])
    assert report.total_workloads == 0
    assert report.resilience_score == 0.0
    assert report.risk_tier == "CRITICAL"

def test_fully_resilient_workloads():
    now = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
    policies = [
        SnapshotPolicy(
            workload_id="VM-SQL-01",
            workload_type="azure_vm",
            tier=1,
            last_snapshot_time=now - timedelta(minutes=30),  # 0.5h <= 1h
            immutable_lock=True,
            secondary_vault_replicated=True,
            purge_protection_enabled=True,
            encryption_cmk=True,
            last_restore_test_date=now - timedelta(days=10),
            snapshot_retention_days=90,
            data_size_gb=500.0,
        ),
        SnapshotPolicy(
            workload_id="BLOB-DOCS-02",
            workload_type="blob_storage",
            tier=2,
            last_snapshot_time=now - timedelta(hours=2),  # 2h <= 4h
            immutable_lock=True,
            secondary_vault_replicated=True,
            purge_protection_enabled=True,
            encryption_cmk=True,
            last_restore_test_date=now - timedelta(days=20),
            snapshot_retention_days=30,
            data_size_gb=1200.0,
        )
    ]
    report = calculate_resilience("CLI-CORP-01", policies, audit_time=now)
    assert report.total_workloads == 2
    assert report.resilience_score == 100.0
    assert report.risk_tier == "RESILIENT"
    assert report.immutable_coverage_pct == 100.0
    assert report.drill_compliance_pct == 100.0
    assert len(report.work_orders) == 0

def test_vulnerable_workload_triggers_work_orders():
    now = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
    policies = [
        SnapshotPolicy(
            workload_id="VM-ERP-01",
            workload_type="azure_vm",
            tier=1,
            last_snapshot_time=now - timedelta(hours=6),  # stale: 6h vs 1h
            immutable_lock=False,  # no WORM lock
            secondary_vault_replicated=False,  # no air gap
            purge_protection_enabled=False,  # purge unprotected
            encryption_cmk=False,
            last_restore_test_date=None,  # never tested
            snapshot_retention_days=7,
            data_size_gb=2000.0,
        )
    ]
    report = calculate_resilience("CLI-RISK-02", policies, audit_time=now)
    assert report.total_workloads == 1
    assert report.resilience_score < 50.0
    assert report.risk_tier == "CRITICAL"
    assert report.immutable_coverage_pct == 0.0
    assert report.drill_compliance_pct == 0.0
    categories = [wo.category for wo in report.work_orders]
    assert "RPO_BREACH" in categories
    assert "RANSOMWARE_EXPOSURE" in categories
    assert "AIRGAP_MISSING" in categories
    assert "KEY_VAULT_SECURITY" in categories
    assert "NO_RESTORE_DRILL" in categories

def test_api_endpoint_recovery_resilience():
    payload = {
        "client_id": "CLIENT-MSP-99",
        "policies": [
            {
                "workload_id": "DB-CORE",
                "workload_type": "sql_database",
                "tier": 1,
                "last_snapshot_time": "2026-11-24T11:45:00Z",
                "immutable_lock": True,
                "secondary_vault_replicated": True,
                "purge_protection_enabled": True,
                "encryption_cmk": True,
                "last_restore_test_date": "2026-11-10T00:00:00Z",
                "snapshot_retention_days": 60,
                "data_size_gb": 350.0
            }
        ]
    }
    resp = client.post("/recovery/resilience", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["client_id"] == "CLIENT-MSP-99"
    assert data["total_workloads"] == 1
    assert data["resilience_score"] >= 85.0
    assert data["risk_tier"] == "RESILIENT"
    assert data["immutable_coverage_pct"] == 100.0
