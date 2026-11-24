"""Automated SMB1001 cybersecurity standard posture auditing and tier compliance verification."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class SMBTier(str, Enum):
    NONE = "NONE"
    BRONZE = "BRONZE"
    SILVER = "SILVER"
    GOLD = "GOLD"


@dataclass
class TierCompliance:
    tier: str
    is_compliant: bool
    score_pct: float
    controls_passed: int
    controls_total: int
    unmet_controls: List[str] = field(default_factory=list)


@dataclass
class RemediationAction:
    control_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    target_tier: str


@dataclass
class SMB1001Report:
    tenant_id: str
    tenant_name: str
    achieved_tier: str
    overall_score_pct: float
    bronze: TierCompliance
    silver: TierCompliance
    gold: TierCompliance
    remediation_actions: List[RemediationAction] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "achieved_tier": self.achieved_tier,
            "overall_score_pct": round(self.overall_score_pct, 1),
            "bronze": {
                "compliant": self.bronze.is_compliant,
                "score_pct": round(self.bronze.score_pct, 1),
                "controls_passed": self.bronze.controls_passed,
                "controls_total": self.bronze.controls_total,
                "unmet_controls": self.bronze.unmet_controls,
            },
            "silver": {
                "compliant": self.silver.is_compliant,
                "score_pct": round(self.silver.score_pct, 1),
                "controls_passed": self.silver.controls_passed,
                "controls_total": self.silver.controls_total,
                "unmet_controls": self.silver.unmet_controls,
            },
            "gold": {
                "compliant": self.gold.is_compliant,
                "score_pct": round(self.gold.score_pct, 1),
                "controls_passed": self.gold.controls_passed,
                "controls_total": self.gold.controls_total,
                "unmet_controls": self.gold.unmet_controls,
            },
            "remediation_actions": [
                {
                    "control_id": r.control_id,
                    "severity": r.severity,
                    "title": r.title,
                    "description": r.description,
                    "target_tier": r.target_tier,
                }
                for r in self.remediation_actions
            ],
            "summary": self.summary,
        }


class SMB1001Auditor:
    """Evaluates multi-tenant infrastructure against SMB1001 Bronze, Silver, and Gold cyber tiers."""

    @staticmethod
    def audit_tenant(posture: Dict[str, Any]) -> SMB1001Report:
        tenant_id = str(posture.get("tenant_id", "tenant-unknown"))
        tenant_name = str(posture.get("tenant_name", "Unknown Tenant"))

        # --- Bronze Controls (Tier 1: Essential Cyber Hygiene) ---
        bronze_unmet: List[str] = []
        bronze_remediations: List[RemediationAction] = []
        b_passed = 0
        b_total = 5

        # B1: MFA on 100% of admin/remote accounts
        mfa_admin = float(posture.get("mfa_admin_pct", 0.0))
        if mfa_admin >= 1.0:
            b_passed += 1
        else:
            bronze_unmet.append("B1_MFA_ADMIN")
            bronze_remediations.append(
                RemediationAction(
                    control_id="B1_MFA_ADMIN",
                    severity="CRITICAL",
                    title="Enforce MFA for Privileged Accounts",
                    description=f"Admin MFA coverage is {mfa_admin * 100:.1f}%. Require MFA for 100% of admin and remote access accounts.",
                    target_tier="BRONZE",
                )
            )

        # B2: Immutable / isolated daily backups
        immutable_backup = bool(posture.get("immutable_backups_enabled", False))
        backup_freq = int(posture.get("backup_frequency_hours", 48))
        if immutable_backup and backup_freq <= 24:
            b_passed += 1
        else:
            bronze_unmet.append("B2_IMMUTABLE_DAILY_BACKUP")
            bronze_remediations.append(
                RemediationAction(
                    control_id="B2_IMMUTABLE_DAILY_BACKUP",
                    severity="CRITICAL",
                    title="Enable Daily Immutable Backups",
                    description="Configure automated daily backup snapshots with object locking or immutable isolation against ransomware.",
                    target_tier="BRONZE",
                )
            )

        # B3: Patch SLA <= 14 days for criticals
        patch_sla = int(posture.get("critical_patch_sla_days", 999))
        if patch_sla <= 14:
            b_passed += 1
        else:
            bronze_unmet.append("B3_PATCH_SLA")
            bronze_remediations.append(
                RemediationAction(
                    control_id="B3_PATCH_SLA",
                    severity="HIGH",
                    title="Enforce 14-Day Critical Patch SLA",
                    description=f"Current critical patch cycle is {patch_sla} days. Maintain automated patching under 14 days.",
                    target_tier="BRONZE",
                )
            )

        # B4: AV / Endpoint coverage >= 95%
        av_cov = float(posture.get("endpoint_av_coverage_pct", 0.0))
        if av_cov >= 0.95:
            b_passed += 1
        else:
            bronze_unmet.append("B4_ENDPOINT_AV")
            bronze_remediations.append(
                RemediationAction(
                    control_id="B4_ENDPOINT_AV",
                    severity="HIGH",
                    title="Deploy Antivirus Across All Endpoints",
                    description=f"Endpoint AV coverage is {av_cov * 100:.1f}%. Minimum required threshold is 95%.",
                    target_tier="BRONZE",
                )
            )

        # B5: Standard users without local admin rights
        least_priv = bool(posture.get("least_privilege_enforced", False))
        if least_priv:
            b_passed += 1
        else:
            bronze_unmet.append("B5_LEAST_PRIVILEGE")
            bronze_remediations.append(
                RemediationAction(
                    control_id="B5_LEAST_PRIVILEGE",
                    severity="HIGH",
                    title="Remove Local Administrative Rights",
                    description="Revoke default local administrator privileges from standard user accounts.",
                    target_tier="BRONZE",
                )
            )

        bronze_score = (b_passed / b_total) * 100.0
        bronze_compliant = b_passed == b_total
        bronze_result = TierCompliance(
            tier="BRONZE",
            is_compliant=bronze_compliant,
            score_pct=bronze_score,
            controls_passed=b_passed,
            controls_total=b_total,
            unmet_controls=bronze_unmet,
        )

        # --- Silver Controls (Tier 2: Managed Security & Defense) ---
        silver_unmet: List[str] = []
        silver_remediations: List[RemediationAction] = []
        s_passed = 0
        s_total = 5

        # S1: EDR coverage >= 90%
        edr_cov = float(posture.get("edr_coverage_pct", 0.0))
        if edr_cov >= 0.90:
            s_passed += 1
        else:
            silver_unmet.append("S1_EDR_COVERAGE")
            silver_remediations.append(
                RemediationAction(
                    control_id="S1_EDR_COVERAGE",
                    severity="HIGH",
                    title="Deploy Centralized EDR",
                    description=f"EDR coverage is {edr_cov * 100:.1f}%. Silver tier requires >= 90% active endpoint agent coverage.",
                    target_tier="SILVER",
                )
            )

        # S2: Network segmentation enabled
        net_seg = bool(posture.get("network_segmentation_enabled", False))
        if net_seg:
            s_passed += 1
        else:
            silver_unmet.append("S2_NETWORK_SEGMENTATION")
            silver_remediations.append(
                RemediationAction(
                    control_id="S2_NETWORK_SEGMENTATION",
                    severity="MEDIUM",
                    title="Implement Network Segmentation",
                    description="Isolate guest, IoT, and internal server VLANs with firewall policy inspection.",
                    target_tier="SILVER",
                )
            )

        # S3: Incident response plan documented & current
        irp_ok = bool(posture.get("incident_response_plan_documented", False))
        if irp_ok:
            s_passed += 1
        else:
            silver_unmet.append("S3_INCIDENT_PLAN")
            silver_remediations.append(
                RemediationAction(
                    control_id="S3_INCIDENT_PLAN",
                    severity="MEDIUM",
                    title="Establish Incident Response Runbook",
                    description="Document step-by-step incident containment procedures and escalation contact hierarchy.",
                    target_tier="SILVER",
                )
            )

        # S4: Inactive account revocation <= 30 days
        inactive_days = int(posture.get("inactive_account_revocation_days", 999))
        if inactive_days <= 30:
            s_passed += 1
        else:
            silver_unmet.append("S4_ACCOUNT_LIFECYCLE")
            silver_remediations.append(
                RemediationAction(
                    control_id="S4_ACCOUNT_LIFECYCLE",
                    severity="MEDIUM",
                    title="Automate Inactive Account Deprovisioning",
                    description=f"Inactive accounts currently persist for {inactive_days} days. Revoke inactive identities within 30 days.",
                    target_tier="SILVER",
                )
            )

        # S5: Disk encryption on laptops >= 90%
        disk_enc = float(posture.get("disk_encryption_pct", 0.0))
        if disk_enc >= 0.90:
            s_passed += 1
        else:
            silver_unmet.append("S5_DISK_ENCRYPTION")
            silver_remediations.append(
                RemediationAction(
                    control_id="S5_DISK_ENCRYPTION",
                    severity="HIGH",
                    title="Enforce Full-Disk Encryption",
                    description=f"Disk encryption coverage is {disk_enc * 100:.1f}%. Minimum required threshold is 90%.",
                    target_tier="SILVER",
                )
            )

        silver_score = (s_passed / s_total) * 100.0
        silver_compliant = bronze_compliant and (s_passed == s_total)
        silver_result = TierCompliance(
            tier="SILVER",
            is_compliant=silver_compliant,
            score_pct=silver_score,
            controls_passed=s_passed,
            controls_total=s_total,
            unmet_controls=silver_unmet,
        )

        # --- Gold Controls (Tier 3: Enterprise Assurance & Continuous Verification) ---
        gold_unmet: List[str] = []
        gold_remediations: List[RemediationAction] = []
        g_passed = 0
        g_total = 4

        # G1: Centralized SIEM audit logging >= 90 days retention
        siem_days = int(posture.get("siem_logging_retention_days", 0))
        if siem_days >= 90:
            g_passed += 1
        else:
            gold_unmet.append("G1_SIEM_LOGGING")
            gold_remediations.append(
                RemediationAction(
                    control_id="G1_SIEM_LOGGING",
                    severity="MEDIUM",
                    title="Maintain 90-Day Centralized Audit Logs",
                    description=f"Log retention is {siem_days} days. Centralize tamper-resistant security logs for >= 90 days.",
                    target_tier="GOLD",
                )
            )

        # G2: Monthly automated vulnerability scans
        vuln_freq = int(posture.get("vulnerability_scan_frequency_days", 999))
        if vuln_freq <= 30:
            g_passed += 1
        else:
            gold_unmet.append("G2_VULNERABILITY_SCAN")
            gold_remediations.append(
                RemediationAction(
                    control_id="G2_VULNERABILITY_SCAN",
                    severity="MEDIUM",
                    title="Schedule Monthly Vulnerability Assessments",
                    description=f"Scan frequency is every {vuln_freq} days. Perform automated asset scans at least every 30 days.",
                    target_tier="GOLD",
                )
            )

        # G3: Supply chain & vendor risk assessed
        vendor_risk = bool(posture.get("supply_chain_risk_assessed", False))
        if vendor_risk:
            g_passed += 1
        else:
            gold_unmet.append("G3_SUPPLY_CHAIN_ASSURANCE")
            gold_remediations.append(
                RemediationAction(
                    control_id="G3_SUPPLY_CHAIN_ASSURANCE",
                    severity="LOW",
                    title="Conduct Annual Supply Chain Risk Reviews",
                    description="Establish annual security assessment reviews for third-party vendors and critical software suppliers.",
                    target_tier="GOLD",
                )
            )

        # G4: Annual penetration testing or ZTNA conditional access
        ztna = bool(posture.get("ztna_conditional_access_enabled", False))
        pen_test = bool(posture.get("annual_penetration_tested", False))
        if ztna or pen_test:
            g_passed += 1
        else:
            gold_unmet.append("G4_ZTNA_OR_PEN_TEST")
            gold_remediations.append(
                RemediationAction(
                    control_id="G4_ZTNA_OR_PEN_TEST",
                    severity="MEDIUM",
                    title="Implement Zero Trust Conditional Access or Pen Testing",
                    description="Deploy device-compliance conditional access or conduct annual external penetration testing.",
                    target_tier="GOLD",
                )
            )

        gold_score = (g_passed / g_total) * 100.0
        gold_compliant = silver_compliant and (g_passed == g_total)
        gold_result = TierCompliance(
            tier="GOLD",
            is_compliant=gold_compliant,
            score_pct=gold_score,
            controls_passed=g_passed,
            controls_total=g_total,
            unmet_controls=gold_unmet,
        )

        # Determine achieved tier
        if gold_compliant:
            achieved = SMBTier.GOLD.value
        elif silver_compliant:
            achieved = SMBTier.SILVER.value
        elif bronze_compliant:
            achieved = SMBTier.BRONZE.value
        else:
            achieved = SMBTier.NONE.value

        total_controls = b_total + s_total + g_total
        passed_controls = b_passed + s_passed + g_passed
        overall_score = (passed_controls / total_controls) * 100.0

        all_remediations = bronze_remediations + silver_remediations + gold_remediations

        summary = (
            f"Tenant {tenant_name} achieved SMB1001 {achieved} Tier "
            f"({passed_controls}/{total_controls} controls passed, overall score {overall_score:.1f}%). "
            f"{len(all_remediations)} remediation actions identified."
        )

        return SMB1001Report(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            achieved_tier=achieved,
            overall_score_pct=overall_score,
            bronze=bronze_result,
            silver=silver_result,
            gold=gold_result,
            remediation_actions=all_remediations,
            summary=summary,
        )
