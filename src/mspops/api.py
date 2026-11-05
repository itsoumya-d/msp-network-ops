from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel, Field

from mspops.assets import client_summary, risk_flags
from mspops.models import Asset, Event, Ticket
from mspops.netops import check_compliance, outage_triage
from mspops.tickets import breach_summary, triage


class TicketIn(BaseModel):
    ticket_id: str
    subject: str
    description: str = ""
    client: str
    impact: str = "single"
    urgency: str = "medium"


class AssetIn(BaseModel):
    asset_id: str
    client: str
    kind: str
    model: str
    warranty_end: str = ""
    eol_date: str = ""
    backup_enabled: bool = True
    last_seen_days: int = 0


class EventIn(BaseModel):
    event_id: str
    site: str
    device: str
    state: str
    severity: str = "high"


app = FastAPI(title="MSP and network ops automation", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/tickets/triage")
def triage_ticket(payload: TicketIn) -> dict[str, object]:
    ticket = Ticket(
        ticket_id=payload.ticket_id,
        subject=payload.subject,
        description=payload.description,
        client=payload.client,
        impact=payload.impact,
        urgency=payload.urgency,
        created_at=datetime.now(timezone.utc),
    )
    result = triage(ticket)
    return result.__dict__ | {"due_at": result.due_at.isoformat()}


@app.post("/tickets/breaches")
def ticket_breaches(payload: list[TicketIn]) -> dict[str, int]:
    tickets = [
        Ticket(
            ticket_id=p.ticket_id,
            subject=p.subject,
            description=p.description,
            client=p.client,
            impact=p.impact,
            urgency=p.urgency,
        )
        for p in payload
    ]
    return breach_summary(tickets)


@app.post("/assets/risk")
def asset_risk(payload: list[AssetIn]) -> dict[str, object]:
    assets = [
        Asset(
            asset_id=p.asset_id,
            client=p.client,
            kind=p.kind,
            model=p.model,
            warranty_end=p.warranty_end,
            eol_date=p.eol_date,
            backup_enabled=p.backup_enabled,
            last_seen_days=p.last_seen_days,
        )
        for p in payload
    ]
    return client_summary(assets)


@app.post("/netops/compliance")
def compliance(config: dict) -> dict[str, object]:
    violations = check_compliance(config)
    return {"compliant": not violations, "violations": violations}


@app.post("/netops/outage")
def outage(events: list[EventIn]) -> dict[str, object]:
    return outage_triage([Event(**e.model_dump()) for e in events])
