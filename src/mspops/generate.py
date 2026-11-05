from __future__ import annotations

import json
from pathlib import Path


def demo() -> dict[str, object]:
    return {
        "tickets": [
            {"ticket_id": "T-1001", "subject": "Site VPN down", "description": "All staff at Auckland site cannot reach files", "client": "Kauri Ltd", "impact": "site", "urgency": "critical"},
            {"ticket_id": "T-1002", "subject": "Outlook mailbox full", "description": "User cannot send email", "client": "Kauri Ltd", "impact": "single", "urgency": "medium"},
            {"ticket_id": "T-1003", "subject": "Suspicious MFA prompt", "description": "Repeated login prompts overnight", "client": "Tui Ltd", "impact": "team", "urgency": "high"},
        ],
        "assets": [
            {"asset_id": "A-1", "client": "Kauri Ltd", "kind": "firewall", "model": "FortiGate 60F", "warranty_end": "2026-12-01", "eol_date": "2028-01-01", "backup_enabled": True, "last_seen_days": 1},
            {"asset_id": "A-2", "client": "Kauri Ltd", "kind": "switch", "model": "Cisco C1000", "warranty_end": "2025-06-01", "eol_date": "2026-01-01", "backup_enabled": False, "last_seen_days": 45},
        ],
        "config": {"telnet_enabled": True, "ssh_v2": True, "ntp_servers": ["10.0.0.10"], "snmp_v3": False, "config_backup_days": 14, "firmware_supported": True, "default_password_changed": True},
        "events": [
            {"event_id": "E-1", "site": "Auckland", "device": "core-sw-1", "state": "down"},
            {"event_id": "E-2", "site": "Auckland", "device": "edge-fw-1", "state": "down"},
            {"event_id": "E-3", "site": "Hamilton", "device": "ap-3", "state": "down"},
        ],
    }


def main() -> None:
    path = Path("data/demo.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(demo(), indent=2))
    print(path)


if __name__ == "__main__":
    main()
