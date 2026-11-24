"""Cloud backup, snapshot recovery, and ransomware resilience posture verification for MSP client environments."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

@dataclass
class SnapshotPolicy:
    workload_id: str
    workload_type: str  # "azure_vm", "blob_storage", "sql_database", "m365_exchange", "m365_sharepoint"
    tier: int  # 1 = mission-critical, 2 = business-standard, 3 = archive
    last_snapshot_time: datetime
    immutable_lock: bool
    secondary_vault_replicated: bool
    purge_protection_enabled: bool
    encryption_cmk: bool
    last_restore_test_date: Optional[datetime]
    snapshot_retention_days: int
    data_size_gb: float

@dataclass
class RemediationOrder:
    order_id: str
    workload_id: str
    priority: str  # "P1", "P2", "P3"
    category: str
    action: str
    technician_runbook: str

@dataclass
class ResilienceAuditReport:
    client_id: str
    total_workloads: int
    resilience_score: float  # 0.0 - 100.0
    risk_tier: str  # "CRITICAL", "ELEVATED", "MODERATE", "RESILIENT"
    actual_rpo_hours: float
    estimated_rto_hours: float
    immutable_coverage_pct: float
    drill_compliance_pct: float
    work_orders: List[RemediationOrder] = field(default_factory=list)


def calculate_resilience(client_id: str, policies: List[SnapshotPolicy], audit_time: Optional[datetime] = None) -> ResilienceAuditReport:
    """Audit cloud backup snapshots for immutable ransomware defense and restore readiness."""
    if not policies:
        return ResilienceAuditReport(
            client_id=client_id,
            total_workloads=0,
            resilience_score=0.0,
            risk_tier="CRITICAL",
            actual_rpo_hours=0.0,
            estimated_rto_hours=0.0,
            immutable_coverage_pct=0.0,
            drill_compliance_pct=0.0,
            work_orders=[]
        )

    now = audit_time or datetime.now(timezone.utc)
    work_orders: List[RemediationOrder] = []
    
    total_score = 0.0
    immutable_count = 0
    drilled_count = 0
    max_rpo_hours = 0.0
    total_rto_hours = 0.0

    for idx, p in enumerate(policies):
        item_score = 100.0
        rpo_hours = max(0.0, (now - p.last_snapshot_time).total_seconds() / 3600.0)
        max_rpo_hours = max(max_rpo_hours, rpo_hours)

        # 1. RPO Threshold check (Tier 1 <= 1h, Tier 2 <= 4h, Tier 3 <= 24h)
        target_rpo = 1.0 if p.tier == 1 else (4.0 if p.tier == 2 else 24.0)
        if rpo_hours > target_rpo:
            penalty = min(30.0, (rpo_hours - target_rpo) * 5.0)
            item_score -= penalty
            work_orders.append(RemediationOrder(
                order_id=f"WO-RPO-{idx+1:03d}",
                workload_id=p.workload_id,
                priority="P1" if p.tier == 1 else "P2",
                category="RPO_BREACH",
                action=f"Snapshot stale: {rpo_hours:.1f}h vs target {target_rpo:.1f}h",
                technician_runbook="Investigate backup agent scheduler and trigger immediate cloud snapshot."
            ))

        # 2. Immutable Object Lock / WORM
        if p.immutable_lock:
            immutable_count += 1
        else:
            item_score -= 25.0
            work_orders.append(RemediationOrder(
                order_id=f"WO-WORM-{idx+1:03d}",
                workload_id=p.workload_id,
                priority="P1" if p.tier == 1 else "P2",
                category="RANSOMWARE_EXPOSURE",
                action="Enable immutable WORM snapshot lock / retention compliance",
                technician_runbook="Apply Azure Backup Vault immutable vault policy in compliance mode."
            ))

        # 3. Secondary Vault / Geo-redundant air gap
        if not p.secondary_vault_replicated:
            item_score -= 15.0
            work_orders.append(RemediationOrder(
                order_id=f"WO-AIRGAP-{idx+1:03d}",
                workload_id=p.workload_id,
                priority="P2",
                category="AIRGAP_MISSING",
                action="Replicate snapshots to isolated secondary recovery vault",
                technician_runbook="Configure cross-region or cross-subscription vault replication."
            ))

        # 4. Key Vault Purge Protection & CMK
        if not p.purge_protection_enabled:
            item_score -= 10.0
            work_orders.append(RemediationOrder(
                order_id=f"WO-PURGE-{idx+1:03d}",
                workload_id=p.workload_id,
                priority="P2",
                category="KEY_VAULT_SECURITY",
                action="Enable Key Vault purge protection and soft-delete",
                technician_runbook="Run az keyvault update --name <vault> --enable-purge-protection true"
            ))

        # 5. Restore Drill Verification (within 30 days)
        if p.last_restore_test_date:
            drill_age_days = (now - p.last_restore_test_date).total_seconds() / 86400.0
            if drill_age_days <= 30.0:
                drilled_count += 1
            else:
                item_score -= 15.0
                work_orders.append(RemediationOrder(
                    order_id=f"WO-DRILL-{idx+1:03d}",
                    workload_id=p.workload_id,
                    priority="P3",
                    category="STALE_RESTORE_DRILL",
                    action=f"Restore drill outdated ({int(drill_age_days)} days ago)",
                    technician_runbook="Execute automated test restore into sandboxed staging resource group."
                ))
        else:
            item_score -= 20.0
            work_orders.append(RemediationOrder(
                order_id=f"WO-DRILL-{idx+1:03d}",
                workload_id=p.workload_id,
                priority="P2",
                category="NO_RESTORE_DRILL",
                action="No documented restore test drill on record",
                technician_runbook="Schedule initial dry-run recovery drill and document RTO timing."
            ))

        # Estimated RTO calculation: base 0.5h + 0.1h per 100GB
        workload_rto = 0.5 + (p.data_size_gb / 1000.0) * 1.5
        total_rto_hours += workload_rto

        total_score += max(0.0, min(100.0, item_score))

    n = len(policies)
    final_score = round(total_score / n, 1)
    immutable_pct = round((immutable_count / n) * 100.0, 1)
    drill_pct = round((drilled_count / n) * 100.0, 1)

    if final_score >= 85.0:
        risk_tier = "RESILIENT"
    elif final_score >= 70.0:
        risk_tier = "MODERATE"
    elif final_score >= 50.0:
        risk_tier = "ELEVATED"
    else:
        risk_tier = "CRITICAL"

    return ResilienceAuditReport(
        client_id=client_id,
        total_workloads=n,
        resilience_score=final_score,
        risk_tier=risk_tier,
        actual_rpo_hours=round(max_rpo_hours, 2),
        estimated_rto_hours=round(total_rto_hours, 2),
        immutable_coverage_pct=immutable_pct,
        drill_compliance_pct=drill_pct,
        work_orders=work_orders
    )
