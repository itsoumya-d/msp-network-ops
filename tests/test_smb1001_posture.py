from fastapi.testclient import TestClient

from mspops.api import app
from mspops.smb1001_posture import SMB1001Auditor, SMBTier

client = TestClient(app)


def test_smb1001_gold_tier_compliance():
    posture = {
        "tenant_id": "tenant-gold-101",
        "tenant_name": "Acme Cloud Enterprise",
        "mfa_admin_pct": 1.0,
        "mfa_all_users_pct": 1.0,
        "immutable_backups_enabled": True,
        "backup_frequency_hours": 12,
        "critical_patch_sla_days": 7,
        "endpoint_av_coverage_pct": 1.0,
        "least_privilege_enforced": True,
        "edr_coverage_pct": 0.98,
        "network_segmentation_enabled": True,
        "incident_response_plan_documented": True,
        "inactive_account_revocation_days": 15,
        "disk_encryption_pct": 0.99,
        "siem_logging_retention_days": 180,
        "vulnerability_scan_frequency_days": 14,
        "supply_chain_risk_assessed": True,
        "annual_penetration_tested": True,
        "ztna_conditional_access_enabled": True,
    }
    report = SMB1001Auditor.audit_tenant(posture)

    assert report.achieved_tier == SMBTier.GOLD.value
    assert report.overall_score_pct == 100.0
    assert report.bronze.is_compliant is True
    assert report.silver.is_compliant is True
    assert report.gold.is_compliant is True
    assert len(report.remediation_actions) == 0


def test_smb1001_bronze_tier_compliance():
    posture = {
        "tenant_id": "tenant-bronze-202",
        "tenant_name": "Midwest Retailers",
        "mfa_admin_pct": 1.0,
        "immutable_backups_enabled": True,
        "backup_frequency_hours": 24,
        "critical_patch_sla_days": 14,
        "endpoint_av_coverage_pct": 0.96,
        "least_privilege_enforced": True,
        # Fails silver controls (no EDR, no network segmentation)
        "edr_coverage_pct": 0.40,
        "network_segmentation_enabled": False,
        "incident_response_plan_documented": False,
        "inactive_account_revocation_days": 60,
        "disk_encryption_pct": 0.50,
        "siem_logging_retention_days": 30,
        "vulnerability_scan_frequency_days": 90,
    }
    report = SMB1001Auditor.audit_tenant(posture)

    assert report.achieved_tier == SMBTier.BRONZE.value
    assert report.bronze.is_compliant is True
    assert report.silver.is_compliant is False
    assert report.gold.is_compliant is False
    assert "S1_EDR_COVERAGE" in report.silver.unmet_controls
    assert "S2_NETWORK_SEGMENTATION" in report.silver.unmet_controls
    assert len(report.remediation_actions) > 0


def test_smb1001_non_compliant_gaps_and_remediations():
    posture = {
        "tenant_id": "tenant-risk-303",
        "tenant_name": "Vulnerable Corp",
        "mfa_admin_pct": 0.20,
        "immutable_backups_enabled": False,
        "backup_frequency_hours": 72,
        "critical_patch_sla_days": 45,
        "endpoint_av_coverage_pct": 0.60,
        "least_privilege_enforced": False,
    }
    report = SMB1001Auditor.audit_tenant(posture)

    assert report.achieved_tier == SMBTier.NONE.value
    assert report.bronze.is_compliant is False
    assert "B1_MFA_ADMIN" in report.bronze.unmet_controls
    assert "B2_IMMUTABLE_DAILY_BACKUP" in report.bronze.unmet_controls
    critical_rems = [r for r in report.remediation_actions if r.severity == "CRITICAL"]
    assert len(critical_rems) >= 2


def test_api_smb1001_posture_endpoint():
    payload = {
        "tenant_id": "tenant-api-404",
        "tenant_name": "Fast Managed Services",
        "mfa_admin_pct": 1.0,
        "immutable_backups_enabled": True,
        "backup_frequency_hours": 12,
        "critical_patch_sla_days": 10,
        "endpoint_av_coverage_pct": 1.0,
        "least_privilege_enforced": True,
        "edr_coverage_pct": 0.95,
        "network_segmentation_enabled": True,
        "incident_response_plan_documented": True,
        "inactive_account_revocation_days": 20,
        "disk_encryption_pct": 0.95,
        "siem_logging_retention_days": 90,
        "vulnerability_scan_frequency_days": 30,
        "supply_chain_risk_assessed": True,
        "annual_penetration_tested": True,
        "ztna_conditional_access_enabled": True,
    }
    resp = client.post("/security/smb1001-posture", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == "tenant-api-404"
    assert data["achieved_tier"] == "GOLD"
    assert data["overall_score_pct"] == 100.0
    assert data["bronze"]["compliant"] is True
    assert data["silver"]["compliant"] is True
    assert data["gold"]["compliant"] is True
