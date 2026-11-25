"""Automated Microsoft 365 and Azure Cloud tenant security baseline auditing."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class M365Violation:
    control_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    remediation_cmd: str


@dataclass
class M365TenantReport:
    tenant_id: str
    tenant_name: str
    security_score: float  # 0.0 - 100.0
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    controls_passed: int
    controls_total: int
    passed_controls: List[str] = field(default_factory=list)
    violations: List[M365Violation] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "security_score": round(self.security_score, 1),
            "risk_level": self.risk_level,
            "controls_passed": self.controls_passed,
            "controls_total": self.controls_total,
            "passed_controls": self.passed_controls,
            "violations": [
                {
                    "control_id": v.control_id,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "remediation_cmd": v.remediation_cmd,
                }
                for v in self.violations
            ],
            "summary": self.summary,
        }


class M365TenantAuditor:
    """Evaluates M365 & Entra ID tenant security settings against CIS and Essential Eight baselines."""

    @staticmethod
    def audit_tenant(posture: Dict[str, Any]) -> M365TenantReport:
        tenant_id = str(posture.get("tenant_id", "tenant-unknown"))
        tenant_name = str(posture.get("tenant_name", "Unknown Tenant"))

        passed: List[str] = []
        violations: List[M365Violation] = []
        total_controls = 8

        # 1. Block Legacy Authentication
        if bool(posture.get("legacy_auth_blocked", False)):
            passed.append("M365-01-LEGACY-AUTH")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-01-LEGACY-AUTH",
                    severity="CRITICAL",
                    title="Legacy Authentication Not Blocked",
                    description="Basic auth protocols (POP3, IMAP, SMTP) bypass modern MFA and account protections.",
                    remediation_cmd="Set-TransportConfig -SmtpClientAuthenticationDisabled $true",
                )
            )

        # 2. Privileged Admin MFA
        if bool(posture.get("admin_mfa_enforced", False)):
            passed.append("M365-02-ADMIN-MFA")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-02-ADMIN-MFA",
                    severity="CRITICAL",
                    title="Administrative MFA Missing",
                    description="100% of global and privileged admin accounts must require phishing-resistant MFA.",
                    remediation_cmd="New-MgIdentityConditionalAccessPolicy -DisplayName 'Require MFA for Admins'",
                )
            )

        # 3. Standard User MFA Coverage >= 90%
        user_mfa = float(posture.get("user_mfa_pct", 0.0))
        if user_mfa >= 0.90:
            passed.append("M365-03-USER-MFA")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-03-USER-MFA",
                    severity="HIGH",
                    title="Low Standard User MFA Enrollment",
                    description=f"Current user MFA enrollment is {user_mfa * 100:.1f}%. Minimum acceptable threshold is 90%.",
                    remediation_cmd="Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationRequirements $mfa",
                )
            )

        # 4. Block External Mailbox Auto-Forwarding (Anti-BEC)
        if bool(posture.get("external_forwarding_blocked", False)):
            passed.append("M365-04-AUTO-FORWARDING")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-04-AUTO-FORWARDING",
                    severity="CRITICAL",
                    title="External Mail Forwarding Enabled",
                    description="Automated external inbox forwarding allows attackers to exfiltrate email unnoticed during BEC attacks.",
                    remediation_cmd="Set-OutboundAntiSpamPolicy -Identity Default -AutoForwardingMode Off",
                )
            )

        # 5. Mailbox & Unified Audit Logging
        if bool(posture.get("mailbox_auditing_enabled", False)):
            passed.append("M365-05-AUDIT-LOGGING")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-05-AUDIT-LOGGING",
                    severity="HIGH",
                    title="Mailbox Audit Logging Disabled",
                    description="Audit logs for owner, delegate, and admin actions must be retained for forensic readiness.",
                    remediation_cmd="Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true",
                )
            )

        # 6. Guest Access Lifetime <= 90 Days
        guest_days = int(posture.get("guest_access_expiry_days", 999))
        if guest_days <= 90:
            passed.append("M365-06-GUEST-EXPIRY")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-06-GUEST-EXPIRY",
                    severity="MEDIUM",
                    title="Indefinite Guest User Access",
                    description=f"Guest access expiry is currently set to {guest_days} days. Restrict guest lifespan to <= 90 days.",
                    remediation_cmd="Set-AzureADDirectorySetting -GuestUserExpirationInDays 90",
                )
            )

        # 7. SharePoint & OneDrive External Sharing Restricted
        if bool(posture.get("sharepoint_external_sharing_restricted", False)):
            passed.append("M365-07-SP-SHARING")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-07-SP-SHARING",
                    severity="MEDIUM",
                    title="Anonymous SharePoint Links Allowed",
                    description="Disable 'Anyone with the link' anonymous public sharing across SharePoint and OneDrive.",
                    remediation_cmd="Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly",
                )
            )

        # 8. Break-Glass Emergency Account Configured & Monitored
        if bool(posture.get("breakglass_accounts_monitored", False)):
            passed.append("M365-08-BREAK-GLASS")
        else:
            violations.append(
                M365Violation(
                    control_id="M365-08-BREAK-GLASS",
                    severity="HIGH",
                    title="Emergency Break-Glass Account Alerting Missing",
                    description="Configure cloud-only break-glass emergency admin accounts excluded from CA with real-time alerting.",
                    remediation_cmd="New-AzureRmAlertRule -TargetResourceId $id -Description 'Breakglass Alert'",
                )
            )

        score = (len(passed) / total_controls) * 100.0

        if score >= 90.0:
            risk = "LOW"
        elif score >= 75.0:
            risk = "MEDIUM"
        elif score >= 50.0:
            risk = "HIGH"
        else:
            risk = "CRITICAL"

        summary = (
            f"Tenant {tenant_name} ({tenant_id}) scored {score:.1f}% on M365 security baseline "
            f"({len(passed)}/{total_controls} controls passed). Risk Level: {risk}. "
            f"{len(violations)} drift violation(s) identified."
        )

        return M365TenantReport(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            security_score=score,
            risk_level=risk,
            controls_passed=len(passed),
            controls_total=total_controls,
            passed_controls=passed,
            violations=violations,
            summary=summary,
        )
