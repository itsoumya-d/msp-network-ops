from __future__ import annotations

from typing import List, Literal
from pydantic import BaseModel, Field


class IdentityAccount(BaseModel):
    id: str
    upn: str
    account_type: Literal["user", "admin", "guest", "service_principal"] = "user"
    mfa_registered: bool = False
    privileged_roles: List[str] = Field(default_factory=list)
    days_since_last_login: int = 0
    legacy_auth_enabled: bool = False
    password_never_expires: bool = False


class TenantIdentityAudit(BaseModel):
    tenant_id: str
    accounts: List[IdentityAccount] = Field(default_factory=list)


class EndpointSecurityDevice(BaseModel):
    device_id: str
    hostname: str
    device_type: Literal["firewall", "workstation", "server"] = "workstation"
    vendor: str = "Generic"
    firmware_up_to_date: bool = True
    definitions_age_hours: int = 0
    web_filtering_active: bool = True
    firewall_rules_audited_days_ago: int = 0


class Finding(BaseModel):
    severity: Literal["critical", "high", "medium", "low"]
    category: Literal["identity", "firewall", "endpoint"]
    target: str
    message: str
    remediation: str


class PostureReport(BaseModel):
    tenant_id: str
    score: int
    status: Literal["healthy", "needs_attention", "critical_risk"]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[Finding]


class PostureRequest(BaseModel):
    identity: TenantIdentityAudit
    devices: List[EndpointSecurityDevice] = Field(default_factory=list)


def audit_identity_posture(audit: TenantIdentityAudit) -> List[Finding]:
    """Audits Microsoft 365 / Active Directory identity posture against CIS & MSP standards."""
    findings: List[Finding] = []
    global_admin_count = 0

    for acct in audit.accounts:
        is_admin = acct.account_type == "admin" or bool(acct.privileged_roles)
        if "Global Administrator" in acct.privileged_roles:
            global_admin_count += 1

        # Rule 1: Privileged accounts without MFA are a Critical vulnerability
        if is_admin and not acct.mfa_registered:
            findings.append(Finding(
                severity="critical",
                category="identity",
                target=acct.upn,
                message=f"Privileged account {acct.upn} does not have MFA registered.",
                remediation="Enforce Conditional Access policy requiring Phishing-resistant or standard MFA for all admin roles.",
            ))
        elif not is_admin and not acct.mfa_registered:
            findings.append(Finding(
                severity="high",
                category="identity",
                target=acct.upn,
                message=f"Standard user {acct.upn} lacks MFA registration.",
                remediation="Require registration via Security Defaults or Conditional Access tenant baseline.",
            ))

        # Rule 2: Legacy authentication protocols (IMAP/POP/Basic Auth)
        if acct.legacy_auth_enabled:
            findings.append(Finding(
                severity="high",
                category="identity",
                target=acct.upn,
                message=f"Account {acct.upn} allows legacy authentication protocols.",
                remediation="Block legacy authentication client apps in Microsoft Entra ID Conditional Access.",
            ))

        # Rule 3: Stale guest accounts
        if acct.account_type == "guest" and acct.days_since_last_login > 90:
            findings.append(Finding(
                severity="medium",
                category="identity",
                target=acct.upn,
                message=f"External guest account {acct.upn} has been inactive for {acct.days_since_last_login} days.",
                remediation="Initiate Entra ID Access Review to revoke stale external collaborator access.",
            ))

        # Rule 4: Password never expires without MFA
        if acct.password_never_expires and not acct.mfa_registered:
            findings.append(Finding(
                severity="high",
                category="identity",
                target=acct.upn,
                message=f"Account {acct.upn} has non-expiring password and lacks MFA.",
                remediation="Mandate MFA enrollment or re-enable automated password expiration rotation.",
            ))

    if global_admin_count > 4:
        findings.append(Finding(
            severity="medium",
            category="identity",
            target=audit.tenant_id,
            message=f"Tenant has {global_admin_count} Global Administrators (recommended maximum is 2-4 with PIM).",
            remediation="Implement Privileged Identity Management (PIM) and downgrade standing Global Admin assignments.",
        ))

    return findings


def audit_endpoint_security(devices: List[EndpointSecurityDevice]) -> List[Finding]:
    """Audits firewall and endpoint security posture (e.g., Fortinet, ESET, Defender)."""
    findings: List[Finding] = []

    for dev in devices:
        # Firewall checks
        if dev.device_type == "firewall":
            if not dev.firmware_up_to_date:
                findings.append(Finding(
                    severity="high",
                    category="firewall",
                    target=dev.hostname,
                    message=f"Firewall appliance {dev.hostname} ({dev.vendor}) has outdated firmware.",
                    remediation="Schedule firmware maintenance window to apply latest vendor security patches.",
                ))
            if not dev.web_filtering_active:
                findings.append(Finding(
                    severity="high",
                    category="firewall",
                    target=dev.hostname,
                    message=f"Firewall {dev.hostname} lacks active Web / DNS filtering profile.",
                    remediation="Enable UTM Web Filter and DNS Inspection profile across outbound LAN-to-WAN policies.",
                ))
            if dev.firewall_rules_audited_days_ago > 90:
                findings.append(Finding(
                    severity="medium",
                    category="firewall",
                    target=dev.hostname,
                    message=f"Firewall access control list rules not reviewed for {dev.firewall_rules_audited_days_ago} days.",
                    remediation="Perform quarterly MSP firewall ruleset review and prune unused policy objects.",
                ))

        # Endpoint / Server protection definitions
        else:
            if dev.definitions_age_hours > 120:
                findings.append(Finding(
                    severity="critical",
                    category="endpoint",
                    target=dev.hostname,
                    message=f"{dev.device_type.capitalize()} {dev.hostname} definitions are {dev.definitions_age_hours} hours old.",
                    remediation="Verify endpoint protection agent service state and connectivity to cloud console.",
                ))
            elif dev.definitions_age_hours > 48:
                findings.append(Finding(
                    severity="medium",
                    category="endpoint",
                    target=dev.hostname,
                    message=f"{dev.device_type.capitalize()} {dev.hostname} definitions are {dev.definitions_age_hours} hours old (> 48h).",
                    remediation="Trigger remote endpoint signature update from RMM management console.",
                ))

    return findings


def calculate_posture_score(findings: List[Finding]) -> tuple[int, Literal["healthy", "needs_attention", "critical_risk"]]:
    """Computes a 0-100 posture health score from weighted findings."""
    deductions = {
        "critical": 25,
        "high": 12,
        "medium": 5,
        "low": 2,
    }
    score = 100 - sum(deductions.get(f.severity, 0) for f in findings)
    score = max(0, min(100, score))

    if score >= 85:
        status: Literal["healthy", "needs_attention", "critical_risk"] = "healthy"
    elif score >= 60:
        status = "needs_attention"
    else:
        status = "critical_risk"

    return score, status


def evaluate_posture(identity: TenantIdentityAudit, devices: List[EndpointSecurityDevice] = []) -> PostureReport:
    """Evaluates combined identity and endpoint security posture and returns a structured PostureReport."""
    all_findings = audit_identity_posture(identity) + audit_endpoint_security(devices)
    score, status = calculate_posture_score(all_findings)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return PostureReport(
        tenant_id=identity.tenant_id,
        score=score,
        status=status,
        total_findings=len(all_findings),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        findings=all_findings,
    )
