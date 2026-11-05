from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from mspops.models import Event

COMPLIANCE_RULES = {
    "telnet_disabled": "Telnet must be disabled",
    "ssh_v2": "SSH v2 must be enabled",
    "ntp_configured": "At least one NTP server must be configured",
    "snmp_v3": "SNMPv3 must be used",
    "backup_within_7_days": "Configuration backup must be no older than 7 days",
    "supported_firmware": "Firmware must be supported",
    "default_password_changed": "Default credentials must be changed",
}


def check_compliance(config: dict) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []
    if config.get("telnet_enabled", False):
        violations.append({"rule": "telnet_disabled", "detail": COMPLIANCE_RULES["telnet_disabled"]})
    if not config.get("ssh_v2", False):
        violations.append({"rule": "ssh_v2", "detail": COMPLIANCE_RULES["ssh_v2"]})
    if not config.get("ntp_servers"):
        violations.append({"rule": "ntp_configured", "detail": COMPLIANCE_RULES["ntp_configured"]})
    if not config.get("snmp_v3", False):
        violations.append({"rule": "snmp_v3", "detail": COMPLIANCE_RULES["snmp_v3"]})
    if int(config.get("config_backup_days", 999)) > 7:
        violations.append({"rule": "backup_within_7_days", "detail": COMPLIANCE_RULES["backup_within_7_days"]})
    if not config.get("firmware_supported", False):
        violations.append({"rule": "supported_firmware", "detail": COMPLIANCE_RULES["supported_firmware"]})
    if not config.get("default_password_changed", False):
        violations.append({"rule": "default_password_changed", "detail": COMPLIANCE_RULES["default_password_changed"]})
    return violations


def outage_triage(events: Iterable[Event]) -> dict[str, object]:
    down = [e for e in events if e.state.lower() in {"down", "unreachable", "offline"}]
    by_site: dict[str, list[Event]] = defaultdict(list)
    for event in down:
        by_site[event.site].append(event)
    incidents = []
    for site, site_events in sorted(by_site.items()):
        devices = sorted({e.device for e in site_events})
        if len(devices) >= 2:
            incidents.append({
                "site": site,
                "scope": "site",
                "devices": devices,
                "severity": "critical",
                "runbook": "Check site power, WAN uplink, core switch and ISP circuit; dispatch field engineer if uplink is down.",
            })
        else:
            incidents.append({
                "site": site,
                "scope": "device",
                "devices": devices,
                "severity": "high",
                "runbook": "Check device power, management reachability, recent config change and logs; replace if unreachable.",
            })
    return {"down_devices": len(down), "incidents": incidents}
