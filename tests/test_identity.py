from fastapi.testclient import TestClient

from mspops.api import app
from mspops.identity import (
    EndpointSecurityDevice,
    IdentityAccount,
    TenantIdentityAudit,
    audit_endpoint_security,
    audit_identity_posture,
    calculate_posture_score,
    evaluate_posture,
)

client = TestClient(app)


def test_privileged_admin_without_mfa():
    audit = TenantIdentityAudit(
        tenant_id="contoso-tenant",
        accounts=[
            IdentityAccount(
                id="usr-1",
                upn="admin@contoso.com",
                account_type="admin",
                mfa_registered=False,
                privileged_roles=["Global Administrator"],
            )
        ],
    )
    findings = audit_identity_posture(audit)
    assert any(f.severity == "critical" and "MFA" in f.message for f in findings)


def test_standard_user_and_legacy_auth():
    audit = TenantIdentityAudit(
        tenant_id="contoso-tenant",
        accounts=[
            IdentityAccount(
                id="usr-2",
                upn="user@contoso.com",
                account_type="user",
                mfa_registered=False,
                legacy_auth_enabled=True,
            )
        ],
    )
    findings = audit_identity_posture(audit)
    assert any(f.severity == "high" and "legacy authentication" in f.message for f in findings)
    assert any(f.severity == "high" and "Standard user" in f.message for f in findings)


def test_guest_account_lifecycle():
    audit = TenantIdentityAudit(
        tenant_id="contoso-tenant",
        accounts=[
            IdentityAccount(
                id="gst-1",
                upn="vendor_external#EXT#@contoso.com",
                account_type="guest",
                mfa_registered=True,
                days_since_last_login=120,
            ),
            IdentityAccount(
                id="gst-2",
                upn="active_partner#EXT#@contoso.com",
                account_type="guest",
                mfa_registered=True,
                days_since_last_login=15,
            ),
        ],
    )
    findings = audit_identity_posture(audit)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "120 days" in findings[0].message


def test_excessive_global_admins():
    audit = TenantIdentityAudit(
        tenant_id="contoso-tenant",
        accounts=[
            IdentityAccount(
                id=f"ga-{i}",
                upn=f"admin{i}@contoso.com",
                account_type="admin",
                mfa_registered=True,
                privileged_roles=["Global Administrator"],
            )
            for i in range(6)
        ],
    )
    findings = audit_identity_posture(audit)
    assert any(f.severity == "medium" and "6 Global Administrators" in f.message for f in findings)


def test_endpoint_and_firewall_audit():
    devices = [
        EndpointSecurityDevice(
            device_id="fw-01",
            hostname="akl-edge-fw01",
            device_type="firewall",
            vendor="Fortinet",
            firmware_up_to_date=False,
            web_filtering_active=False,
            firewall_rules_audited_days_ago=105,
        ),
        EndpointSecurityDevice(
            device_id="wk-01",
            hostname="akl-des-042",
            device_type="workstation",
            vendor="ESET",
            definitions_age_hours=130,
        ),
        EndpointSecurityDevice(
            device_id="srv-01",
            hostname="akl-app-srv01",
            device_type="server",
            vendor="Microsoft Defender",
            definitions_age_hours=55,
        ),
    ]
    findings = audit_endpoint_security(devices)
    assert any(f.category == "firewall" and "outdated firmware" in f.message for f in findings)
    assert any(f.category == "firewall" and "DNS filtering" in f.message for f in findings)
    assert any(f.category == "firewall" and "105 days" in f.message for f in findings)
    assert any(f.category == "endpoint" and f.severity == "critical" for f in findings)
    assert any(f.category == "endpoint" and f.severity == "medium" for f in findings)


def test_posture_score_and_evaluation():
    audit = TenantIdentityAudit(
        tenant_id="clean-tenant",
        accounts=[
            IdentityAccount(
                id="usr-ok",
                upn="user@clean.co.nz",
                account_type="user",
                mfa_registered=True,
            )
        ],
    )
    clean_device = [
        EndpointSecurityDevice(
            device_id="fw-clean",
            hostname="fw-primary",
            device_type="firewall",
            vendor="Fortinet",
            firmware_up_to_date=True,
            web_filtering_active=True,
            firewall_rules_audited_days_ago=14,
        )
    ]
    report = evaluate_posture(audit, clean_device)
    assert report.score == 100
    assert report.status == "healthy"
    assert report.total_findings == 0


def test_api_identity_and_posture_endpoints():
    identity_payload = {
        "tenant_id": "test-org",
        "accounts": [
            {
                "id": "1",
                "upn": "admin@test.com",
                "account_type": "admin",
                "mfa_registered": False,
                "privileged_roles": ["Global Administrator"],
            }
        ],
    }
    r = client.post("/identity/audit", json=identity_payload)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 1
    assert data[0]["severity"] == "critical"

    posture_payload = {
        "identity": identity_payload,
        "devices": [
            {
                "device_id": "fw-1",
                "hostname": "firewall-1",
                "device_type": "firewall",
                "vendor": "Fortinet",
                "firmware_up_to_date": False,
            }
        ],
    }
    r2 = client.post("/security/posture", json=posture_payload)
    assert r2.status_code == 200
    report = r2.json()
    assert report["tenant_id"] == "test-org"
    assert report["critical_count"] == 1
    assert report["high_count"] == 1
    assert report["status"] in ["needs_attention", "critical_risk"]
