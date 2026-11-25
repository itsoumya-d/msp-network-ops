from fastapi.testclient import TestClient

from mspops.api import app
from mspops.m365_security import M365TenantAuditor

client = TestClient(app)


def test_m365_tenant_full_compliance():
    posture = {
        "tenant_id": "tenant-m365-clean-001",
        "tenant_name": "Auckland Legal Services",
        "legacy_auth_blocked": True,
        "admin_mfa_enforced": True,
        "user_mfa_pct": 1.0,
        "external_forwarding_blocked": True,
        "mailbox_auditing_enabled": True,
        "guest_access_expiry_days": 60,
        "sharepoint_external_sharing_restricted": True,
        "breakglass_accounts_monitored": True,
    }
    report = M365TenantAuditor.audit_tenant(posture)

    assert report.security_score == 100.0
    assert report.risk_level == "LOW"
    assert report.controls_passed == 8
    assert len(report.violations) == 0


def test_m365_tenant_critical_bec_and_legacy_auth_violations():
    posture = {
        "tenant_id": "tenant-m365-risk-002",
        "tenant_name": "Compromised Retailers",
        "legacy_auth_blocked": False,
        "admin_mfa_enforced": False,
        "user_mfa_pct": 0.40,
        "external_forwarding_blocked": False,
        "mailbox_auditing_enabled": False,
        "guest_access_expiry_days": 180,
        "sharepoint_external_sharing_restricted": False,
        "breakglass_accounts_monitored": False,
    }
    report = M365TenantAuditor.audit_tenant(posture)

    assert report.security_score == 0.0
    assert report.risk_level == "CRITICAL"
    assert len(report.violations) == 8

    crit_ids = [v.control_id for v in report.violations if v.severity == "CRITICAL"]
    assert "M365-01-LEGACY-AUTH" in crit_ids
    assert "M365-02-ADMIN-MFA" in crit_ids
    assert "M365-04-AUTO-FORWARDING" in crit_ids


def test_m365_tenant_partial_compliance():
    posture = {
        "tenant_id": "tenant-m365-mid-003",
        "tenant_name": "Growing Consultancy",
        "legacy_auth_blocked": True,
        "admin_mfa_enforced": True,
        "user_mfa_pct": 0.92,
        "external_forwarding_blocked": True,
        "mailbox_auditing_enabled": True,
        "guest_access_expiry_days": 120,  # violation
        "sharepoint_external_sharing_restricted": False,  # violation
        "breakglass_accounts_monitored": True,
    }
    report = M365TenantAuditor.audit_tenant(posture)

    assert report.security_score == 75.0
    assert report.risk_level == "MEDIUM"
    assert report.controls_passed == 6
    assert len(report.violations) == 2


def test_api_m365_tenant_posture_endpoint():
    payload = {
        "tenant_id": "tenant-api-test-004",
        "tenant_name": "API Monitored Client",
        "legacy_auth_blocked": True,
        "admin_mfa_enforced": True,
        "user_mfa_pct": 0.95,
        "external_forwarding_blocked": True,
        "mailbox_auditing_enabled": True,
        "guest_access_expiry_days": 90,
        "sharepoint_external_sharing_restricted": True,
        "breakglass_accounts_monitored": True,
    }
    resp = client.post("/security/m365-tenant-posture", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["tenant_id"] == "tenant-api-test-004"
    assert data["security_score"] == 100.0
    assert data["risk_level"] == "LOW"
    assert data["controls_passed"] == 8
