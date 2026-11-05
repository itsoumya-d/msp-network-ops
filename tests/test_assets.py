from datetime import date

from mspops.assets import client_summary, risk_flags
from mspops.models import Asset


def asset(**kwargs):
    base = dict(asset_id="A1", client="Kauri", kind="firewall", model="FG-60F",
                warranty_end="2026-12-01", eol_date="2028-01-01",
                backup_enabled=True, last_seen_days=1)
    base.update(kwargs)
    return Asset(**base)


def test_risk_flags():
    flags = risk_flags(asset(warranty_end="2025-01-01", eol_date="2025-01-01", backup_enabled=False, last_seen_days=45),
                       today=date(2026, 11, 5))
    assert {"warranty_expired", "end_of_life", "no_backup", "stale_inventory"}.issubset(flags)


def test_summary_counts():
    summary = client_summary([asset(warranty_end="2027-06-01"), asset(asset_id="A2", backup_enabled=False)], today=date(2026, 11, 5))
    assert summary["assets"] == 2
    assert summary["risky"] == 1
