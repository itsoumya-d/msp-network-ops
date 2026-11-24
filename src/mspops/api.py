from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from mspops.assets import client_summary, risk_flags
from mspops.identity import (
    EndpointSecurityDevice,
    Finding,
    PostureReport,
    PostureRequest,
    TenantIdentityAudit,
    audit_identity_posture,
    evaluate_posture,
)
from mspops.models import Asset, Event, Ticket
from mspops.finops import CostRecord, ResourceMetric, budget_burn, detect_anomalies, recommendations
from mspops.netops import check_compliance, outage_triage
from mspops.resilience import SnapshotPolicy, calculate_resilience
from mspops.email_security import audit_domain_email_security
from mspops.smb1001_posture import SMB1001Auditor
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


class CostRecordIn(BaseModel):
    account: str
    service: str
    month: str
    amount: float


class ResourceMetricIn(BaseModel):
    resource_id: str
    account: str
    service: str
    cpu_pct: float
    memory_pct: float
    attached: bool
    monthly_cost: float


class BudgetIn(BaseModel):
    records: list[CostRecordIn]
    budget: float
    month: str


class SnapshotPolicyIn(BaseModel):
    workload_id: str
    workload_type: str = "azure_vm"
    tier: int = 1
    last_snapshot_time: str
    immutable_lock: bool = True
    secondary_vault_replicated: bool = True
    purge_protection_enabled: bool = True
    encryption_cmk: bool = True
    last_restore_test_date: Optional[str] = None
    snapshot_retention_days: int = 30
    data_size_gb: float = 100.0


class ResilienceAuditIn(BaseModel):
    client_id: str
    policies: list[SnapshotPolicyIn]


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


@app.post("/finops/anomalies")
def finops_anomalies(records: list[CostRecordIn]) -> list[dict]:
    return detect_anomalies([CostRecord(**r.model_dump()) for r in records])


@app.post("/finops/recommendations")
def finops_recommendations(resources: list[ResourceMetricIn]) -> list[dict]:
    return recommendations([ResourceMetric(**r.model_dump()) for r in resources])


@app.post("/finops/budget")
def finops_budget(payload: BudgetIn) -> dict:
    return budget_burn([CostRecord(**r.model_dump()) for r in payload.records], payload.budget, payload.month)


@app.post("/identity/audit")
def identity_audit(payload: TenantIdentityAudit) -> list[dict]:
    findings = audit_identity_posture(payload)
    return [f.model_dump() for f in findings]


@app.post("/security/posture")
def security_posture(payload: PostureRequest) -> dict:
    report = evaluate_posture(payload.identity, payload.devices)
    return report.model_dump()


class EmailSecurityIn(BaseModel):
    domain: str
    spf_raw: Optional[str] = None
    dkim_selector: str = ""
    dkim_key_bits: int = 0
    dmarc_raw: Optional[str] = None
    bimi_raw: Optional[str] = None


@app.post("/recovery/resilience")
def recovery_resilience(payload: ResilienceAuditIn) -> dict:
    policies = []
    for p in payload.policies:
        snap_dt = datetime.fromisoformat(p.last_snapshot_time.replace("Z", "+00:00"))
        test_dt = datetime.fromisoformat(p.last_restore_test_date.replace("Z", "+00:00")) if p.last_restore_test_date else None
        policies.append(SnapshotPolicy(
            workload_id=p.workload_id,
            workload_type=p.workload_type,
            tier=p.tier,
            last_snapshot_time=snap_dt,
            immutable_lock=p.immutable_lock,
            secondary_vault_replicated=p.secondary_vault_replicated,
            purge_protection_enabled=p.purge_protection_enabled,
            encryption_cmk=p.encryption_cmk,
            last_restore_test_date=test_dt,
            snapshot_retention_days=p.snapshot_retention_days,
            data_size_gb=p.data_size_gb,
        ))
    report = calculate_resilience(payload.client_id, policies)
    return asdict(report)


@app.post("/security/email-posture")
def email_security_posture(payload: EmailSecurityIn) -> dict:
    report = audit_domain_email_security(
        domain=payload.domain,
        spf_raw=payload.spf_raw,
        dkim_selector=payload.dkim_selector,
        dkim_key_bits=payload.dkim_key_bits,
        dmarc_raw=payload.dmarc_raw,
        bimi_raw=payload.bimi_raw,
    )
    return report.to_dict()


class SMB1001In(BaseModel):
    tenant_id: str
    tenant_name: str = ""
    mfa_admin_pct: float = 1.0
    mfa_all_users_pct: float = 1.0
    immutable_backups_enabled: bool = True
    backup_frequency_hours: int = 24
    critical_patch_sla_days: int = 14
    endpoint_av_coverage_pct: float = 1.0
    least_privilege_enforced: bool = True
    edr_coverage_pct: float = 0.95
    network_segmentation_enabled: bool = True
    incident_response_plan_documented: bool = True
    inactive_account_revocation_days: int = 30
    disk_encryption_pct: float = 1.0
    siem_logging_retention_days: int = 90
    vulnerability_scan_frequency_days: int = 30
    supply_chain_risk_assessed: bool = True
    annual_penetration_tested: bool = True
    ztna_conditional_access_enabled: bool = True


@app.post("/security/smb1001-posture")
def smb1001_posture(payload: SMB1001In) -> dict:
    data = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    report = SMB1001Auditor.audit_tenant(data)
    return report.to_dict()


