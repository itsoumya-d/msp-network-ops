from __future__ import annotations

from datetime import date, datetime
from typing import Iterable

from mspops.models import Asset


def parse_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def risk_flags(asset: Asset, today: date | None = None) -> list[str]:
    today = today or date.today()
    flags: list[str] = []
    warranty = parse_date(asset.warranty_end)
    eol = parse_date(asset.eol_date)
    if warranty and warranty < today:
        flags.append("warranty_expired")
    elif warranty and (warranty - today).days <= 90:
        flags.append("warranty_expiring")
    if eol and eol < today:
        flags.append("end_of_life")
    if not asset.backup_enabled:
        flags.append("no_backup")
    if asset.last_seen_days > 30:
        flags.append("stale_inventory")
    return flags


def client_summary(assets: Iterable[Asset], today: date | None = None) -> dict[str, object]:
    assets = list(assets)
    flagged = [(a.asset_id, risk_flags(a, today)) for a in assets]
    risky = [asset_id for asset_id, flags in flagged if flags]
    return {
        "assets": len(assets),
        "risky": len(risky),
        "risky_ids": risky,
        "by_flag": {
            flag: sum(1 for _, flags in flagged if flag in flags)
            for flag in ("warranty_expired", "warranty_expiring", "end_of_life", "no_backup", "stale_inventory")
        },
    }
