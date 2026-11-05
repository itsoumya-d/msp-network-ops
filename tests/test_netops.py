from mspops.models import Event
from mspops.netops import check_compliance, outage_triage


def test_compliance_flags():
    violations = check_compliance({"telnet_enabled": True, "ssh_v2": True, "ntp_servers": ["10.0.0.10"],
                                   "snmp_v3": False, "config_backup_days": 14,
                                   "firmware_supported": True, "default_password_changed": True})
    rules = {v["rule"] for v in violations}
    assert rules == {"telnet_disabled", "snmp_v3", "backup_within_7_days"}


def test_site_outage_grouping():
    result = outage_triage([
        Event("E1", "Auckland", "core-sw-1", "down"),
        Event("E2", "Auckland", "edge-fw-1", "down"),
        Event("E3", "Hamilton", "ap-3", "down"),
    ])
    assert result["down_devices"] == 3
    scopes = {i["site"]: i["scope"] for i in result["incidents"]}
    assert scopes == {"Auckland": "site", "Hamilton": "device"}
