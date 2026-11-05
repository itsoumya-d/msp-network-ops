from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


@dataclass
class CostRecord:
    account: str
    service: str
    month: str
    amount: float


@dataclass
class ResourceMetric:
    resource_id: str
    account: str
    service: str
    cpu_pct: float
    memory_pct: float
    attached: bool
    monthly_cost: float


def detect_anomalies(records: list[CostRecord], threshold: float = 0.25, minimum_delta: float = 100.0) -> list[dict]:
    grouped: dict[tuple[str, str], list[CostRecord]] = defaultdict(list)
    for record in records:
        grouped[(record.account, record.service)].append(record)
    anomalies: list[dict] = []
    for (account, service), rows in grouped.items():
        rows.sort(key=lambda r: r.month)
        for previous, current in zip(rows, rows[1:]):
            delta = current.amount - previous.amount
            if previous.amount > 0 and delta > minimum_delta and delta / previous.amount >= threshold:
                anomalies.append({
                    "account": account,
                    "service": service,
                    "month": current.month,
                    "previous": previous.amount,
                    "current": current.amount,
                    "delta": round(delta, 2),
                    "delta_pct": round(delta / previous.amount * 100, 1),
                })
    return anomalies


def recommendations(resources: list[ResourceMetric]) -> list[dict]:
    out: list[dict] = []
    for r in resources:
        if not r.attached:
            out.append({"resource_id": r.resource_id, "action": "delete_unattached", "monthly_saving": round(r.monthly_cost, 2), "reason": "unattached resource"})
        elif r.cpu_pct < 5 and r.memory_pct < 15:
            out.append({"resource_id": r.resource_id, "action": "stop_idle", "monthly_saving": round(r.monthly_cost * 0.8, 2), "reason": "idle CPU/memory"})
        elif r.cpu_pct < 10 and r.memory_pct < 20:
            out.append({"resource_id": r.resource_id, "action": "rightsize_down", "monthly_saving": round(r.monthly_cost * 0.4, 2), "reason": "overprovisioned"})
    return out


def budget_burn(records: list[CostRecord], budget: float, month: str) -> dict:
    spend = round(sum(r.amount for r in records if r.month == month), 2)
    remaining = round(budget - spend, 2)
    burn_pct = round(spend / budget * 100, 1) if budget > 0 else 0.0
    return {"month": month, "spend": spend, "budget": budget, "remaining": remaining, "burn_pct": burn_pct, "over_budget": spend > budget}
