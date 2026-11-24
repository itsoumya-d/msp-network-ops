"""Automated domain email authentication, anti-spoofing governance, and DMARC/SPF/DKIM/BIMI posture auditing."""
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class SPFAnalysis:
    raw: str
    qualifier: str  # "-all", "~all", "?all", "+all", "missing"
    lookup_count: int
    is_valid: bool
    is_permissive: bool
    warnings: List[str] = field(default_factory=list)

@dataclass
class DKIMAnalysis:
    selector: str
    key_size_bits: int
    is_valid: bool
    is_weak_key: bool
    warnings: List[str] = field(default_factory=list)

@dataclass
class DMARCAnalysis:
    raw: str
    policy: str  # "reject", "quarantine", "none", "missing"
    percentage: int
    has_rua: bool
    is_enforcing: bool
    warnings: List[str] = field(default_factory=list)

@dataclass
class BIMIAnalysis:
    has_bimi: bool
    svg_url: Optional[str] = None
    vmc_present: bool = False

@dataclass
class EmailSecurityReport:
    domain: str
    score: float  # 0.0 - 100.0
    security_tier: str  # "SECURE", "ADEQUATE", "VULNERABLE", "CRITICAL_RISK"
    spf: SPFAnalysis
    dkim: DKIMAnalysis
    dmarc: DMARCAnalysis
    bimi: BIMIAnalysis
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "score": round(self.score, 1),
            "security_tier": self.security_tier,
            "spf": {
                "raw": self.spf.raw,
                "qualifier": self.spf.qualifier,
                "lookup_count": self.spf.lookup_count,
                "is_valid": self.spf.is_valid,
                "is_permissive": self.spf.is_permissive,
                "warnings": self.spf.warnings,
            },
            "dkim": {
                "selector": self.dkim.selector,
                "key_size_bits": self.dkim.key_size_bits,
                "is_valid": self.dkim.is_valid,
                "is_weak_key": self.dkim.is_weak_key,
                "warnings": self.dkim.warnings,
            },
            "dmarc": {
                "raw": self.dmarc.raw,
                "policy": self.dmarc.policy,
                "percentage": self.dmarc.percentage,
                "has_rua": self.dmarc.has_rua,
                "is_enforcing": self.dmarc.is_enforcing,
                "warnings": self.dmarc.warnings,
            },
            "bimi": {
                "has_bimi": self.bimi.has_bimi,
                "svg_url": self.bimi.svg_url,
                "vmc_present": self.bimi.vmc_present,
            },
            "remediation_steps": self.remediation_steps,
        }


def parse_spf(raw_spf: Optional[str]) -> SPFAnalysis:
    if not raw_spf or not raw_spf.strip():
        return SPFAnalysis(
            raw="",
            qualifier="missing",
            lookup_count=0,
            is_valid=False,
            is_permissive=True,
            warnings=["No SPF record published. Anyone on the internet can spoof this domain."],
        )

    clean = raw_spf.strip()
    if not clean.lower().startswith("v=spf1"):
        return SPFAnalysis(
            raw=clean,
            qualifier="invalid",
            lookup_count=0,
            is_valid=False,
            is_permissive=True,
            warnings=["SPF record does not begin with 'v=spf1'."],
        )

    terms = clean.split()
    lookup_count = 0
    qualifier = "?all"
    warnings = []

    for term in terms[1:]:
        lower = term.lower()
        if lower.endswith("all"):
            qualifier = lower
        if lower.startswith(("include:", "a:", "mx:", "ptr:", "exists:")) or lower in ("a", "mx", "ptr"):
            lookup_count += 1

    is_permissive = qualifier in ("+all", "all")
    if is_permissive:
        warnings.append("CRITICAL: SPF uses permissive '+all' or bare 'all', allowing all unauthorized servers to send mail.")

    if lookup_count > 10:
        warnings.append(f"SPF record triggers {lookup_count} DNS lookups, exceeding the RFC 7208 limit of 10 (will cause PermError).")

    return SPFAnalysis(
        raw=clean,
        qualifier=qualifier,
        lookup_count=lookup_count,
        is_valid=True,
        is_permissive=is_permissive,
        warnings=warnings,
    )


def parse_dkim(selector: str, key_bits: int) -> DKIMAnalysis:
    warnings = []
    if not selector or key_bits <= 0:
        return DKIMAnalysis(
            selector=selector or "",
            key_size_bits=0,
            is_valid=False,
            is_weak_key=True,
            warnings=["No active DKIM selector configured."],
        )

    is_weak = key_bits < 2048
    if key_bits < 1024:
        warnings.append(f"DKIM key size {key_bits}-bit is cryptographically broken and rejected by major receivers.")
    elif key_bits < 2048:
        warnings.append(f"DKIM key size {key_bits}-bit is deprecated. Upgrade to 2048-bit RSA or Ed25519.")

    return DKIMAnalysis(
        selector=selector,
        key_size_bits=key_bits,
        is_valid=True,
        is_weak_key=is_weak,
        warnings=warnings,
    )


def parse_dmarc(raw_dmarc: Optional[str]) -> DMARCAnalysis:
    if not raw_dmarc or not raw_dmarc.strip():
        return DMARCAnalysis(
            raw="",
            policy="missing",
            percentage=0,
            has_rua=False,
            is_enforcing=False,
            warnings=["No DMARC record published. Receivers cannot reject impersonated emails."],
        )

    clean = raw_dmarc.strip()
    if not clean.lower().startswith("v=dmarc1"):
        return DMARCAnalysis(
            raw=clean,
            policy="missing",
            percentage=0,
            has_rua=False,
            is_enforcing=False,
            warnings=["DMARC record does not start with 'v=DMARC1'."],
        )

    tags: Dict[str, str] = {}
    for part in clean.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()
    pct_str = tags.get("pct", "100")
    try:
        pct = int(pct_str)
    except ValueError:
        pct = 100

    has_rua = "rua" in tags
    is_enforcing = policy in ("reject", "quarantine") and pct == 100
    warnings = []

    if policy == "none":
        warnings.append("DMARC policy is set to 'p=none' (monitoring only). Spoofed emails are delivered without rejection.")
    elif policy == "quarantine":
        warnings.append("DMARC policy is set to 'quarantine'. Recommendation is 'reject' for full impersonation defense.")

    if pct < 100:
        warnings.append(f"DMARC policy enforcement pct is {pct}%, leaving {100 - pct}% of messages unverified.")

    if not has_rua:
        warnings.append("No aggregate feedback reporting (rua) URI configured; blind to spoofing attacks.")

    return DMARCAnalysis(
        raw=clean,
        policy=policy,
        percentage=pct,
        has_rua=has_rua,
        is_enforcing=is_enforcing,
        warnings=warnings,
    )


def parse_bimi(raw_bimi: Optional[str]) -> BIMIAnalysis:
    if not raw_bimi or not raw_bimi.strip():
        return BIMIAnalysis(has_bimi=False)

    clean = raw_bimi.strip()
    has_bimi = clean.lower().startswith("v=bimi1")
    svg_url = None
    vmc_present = False

    for part in clean.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k_clean = k.strip().lower()
            if k_clean == "l":
                svg_url = v.strip()
            elif k_clean == "a":
                vmc_present = bool(v.strip())

    return BIMIAnalysis(has_bimi=has_bimi, svg_url=svg_url, vmc_present=vmc_present)


def audit_domain_email_security(
    domain: str,
    spf_raw: Optional[str] = None,
    dkim_selector: str = "",
    dkim_key_bits: int = 0,
    dmarc_raw: Optional[str] = None,
    bimi_raw: Optional[str] = None,
) -> EmailSecurityReport:
    """Analyze email anti-spoofing posture and compute security score + remediation runbook."""
    spf = parse_spf(spf_raw)
    dkim = parse_dkim(dkim_selector, dkim_key_bits)
    dmarc = parse_dmarc(dmarc_raw)
    bimi = parse_bimi(bimi_raw)

    score = 0.0
    remediations: List[str] = []

    # DMARC Scoring (max 40)
    if dmarc.policy == "reject" and dmarc.percentage == 100:
        score += 40.0
    elif dmarc.policy == "quarantine":
        score += 25.0 * (dmarc.percentage / 100.0)
        remediations.append("Upgrade DMARC policy from 'quarantine' to 'reject' once legitimate senders are confirmed.")
    elif dmarc.policy == "none":
        score += 10.0
        remediations.append("DMARC is in monitoring mode (p=none); update to p=quarantine and then p=reject to block domain spoofing.")
    else:
        remediations.append("Deploy a DMARC TXT record at _dmarc." + domain + " with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + domain + "'.")

    if not dmarc.has_rua:
        remediations.append("Add 'rua=mailto:dmarc@" + domain + "' to receive forensic and aggregate delivery reports.")

    # SPF Scoring (max 30)
    if spf.is_valid and not spf.is_permissive:
        if spf.qualifier == "-all":
            score += 30.0
        elif spf.qualifier == "~all":
            score += 20.0
            remediations.append("Tighten SPF qualifier from softfail (~all) to hardfail (-all).")
        else:
            score += 5.0
            remediations.append("Replace SPF neutral (?all) with hardfail (-all).")
    else:
        remediations.append("Configure a valid SPF record with hardfail (-all) and ensure DNS lookups remain under 10.")

    if spf.lookup_count > 10:
        remediations.append("SPF exceeds 10 DNS lookups; consolidate include mechanisms to avoid PermError.")

    # DKIM Scoring (max 20)
    if dkim.is_valid:
        if dkim.key_size_bits >= 2048:
            score += 20.0
        elif dkim.key_size_bits >= 1024:
            score += 10.0
            remediations.append("Rotate DKIM signing key to 2048-bit RSA or Ed25519.")
        else:
            remediations.append("DKIM key is below 1024 bits; regenerate key pair immediately.")
    else:
        remediations.append("Enable DKIM signing on outbound mail gateway and publish selector DNS record.")

    # BIMI Scoring (max 10)
    if bimi.has_bimi:
        score += 10.0
    elif dmarc.is_enforcing:
        remediations.append("Optional: Publish BIMI record with verified brand logo SVG to enhance sender trust.")

    score = min(100.0, max(0.0, score))

    if score >= 85.0:
        tier = "SECURE"
    elif score >= 65.0:
        tier = "ADEQUATE"
    elif score >= 40.0:
        tier = "VULNERABLE"
    else:
        tier = "CRITICAL_RISK"

    return EmailSecurityReport(
        domain=domain,
        score=score,
        security_tier=tier,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        bimi=bimi,
        remediation_steps=remediations,
    )
