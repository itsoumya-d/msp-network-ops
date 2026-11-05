from fastapi.testclient import TestClient

from mspops.api import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_triage_endpoint():
    response = client.post("/tickets/triage", json={
        "ticket_id": "T1", "subject": "VPN down", "description": "site outage",
        "client": "Kauri", "impact": "site", "urgency": "critical",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "network"
    assert data["priority"] == "P2"


def test_compliance_and_outage_endpoints():
    assert client.post("/netops/compliance", json={"telnet_enabled": True}).json()["compliant"] is False
    outage = client.post("/netops/outage", json=[
        {"event_id": "E1", "site": "Auckland", "device": "core-sw-1", "state": "down"},
        {"event_id": "E2", "site": "Auckland", "device": "edge-fw-1", "state": "down"},
    ]).json()
    assert outage["incidents"][0]["scope"] == "site"
