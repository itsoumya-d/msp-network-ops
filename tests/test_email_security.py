import pytest
from fastapi.testclient import TestClient

from mspops.api import app
from mspops.email_security import (
    audit_domain_email_security,
    parse_spf,
    parse_dkim,
    parse_dmarc,
    parse_bimi,
)

client = TestClient(app)


def test_missing_records_critical_risk():
    report = audit_domain_email_security("example-unsecured.co.nz")
    assert report.score == 0.0
    assert report.security_tier == "CRITICAL_RISK"
    assert report.spf.qualifier == "missing"
    assert report.dmarc.policy == "missing"
    assert len(report.remediation_steps) >= 3


def test_fully_hardened_domain_posture():
    report = audit_domain_email_security(
        domain="secure-client.nz",
        spf_raw="v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
        dkim_selector="m365",
        dkim_key_bits=2048,
        dmarc_raw="v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@secure-client.nz",
        bimi_raw="v=BIMI1; l=https://secure-client.nz/logo.svg; a=https://secure-client.nz/vmc.pem",
    )
    assert report.score == 100.0
    assert report.security_tier == "SECURE"
    assert report.spf.qualifier == "-all"
    assert report.dmarc.is_enforcing is True
    assert report.dkim.is_weak_key is False
    assert report.bimi.has_bimi is True
    assert len(report.remediation_steps) == 0


def test_permissive_spf_and_dmarc_monitoring_warning():
    report = audit_domain_email_security(
        domain="vulnerable-fleet.co.nz",
        spf_raw="v=spf1 +all",
        dkim_selector="default",
        dkim_key_bits=1024,
        dmarc_raw="v=DMARC1; p=none",
    )
    assert report.spf.is_permissive is True
    assert report.dmarc.policy == "none"
    assert report.dkim.is_weak_key is True
    assert report.score < 50.0
    assert report.security_tier in ("VULNERABLE", "CRITICAL_RISK")
    assert any("permissive" in w.lower() or "+all" in w.lower() for w in report.spf.warnings)


def test_api_endpoint_email_posture():
    resp = client.post(
        "/security/email-posture",
        json={
            "domain": "acme-corp.co.nz",
            "spf_raw": "v=spf1 include:spf.protection.outlook.com -all",
            "dkim_selector": "selector1",
            "dkim_key_bits": 2048,
            "dmarc_raw": "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@acme-corp.co.nz",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "acme-corp.co.nz"
    assert data["security_tier"] in ("ADEQUATE", "SECURE")
    assert data["score"] >= 70.0
    assert data["dmarc"]["policy"] == "quarantine"
