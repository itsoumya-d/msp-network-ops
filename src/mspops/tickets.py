from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from mspops.models import Priority, Ticket, TriageResult

CATEGORY_RULES = [
    ("security", r"phish|ransom|malware|breach|suspicious|mfa|compromis|security"),
    ("network", r"vpn|firewall|switch|router|wifi|wi-fi|latency|packet|dns|dhcp|uplink|network"),
    ("email", r"outlook|exchange|mailbox|email|smtp|spam|m365|microsoft 365"),
    ("backup", r"backup|restore|snapshot|veeam|replication"),
    ("access", r"password|login|locked|access|permission|mfa reset|account"),
    ("erp", r"erp|dynamics|sap|netsuite|business central|xero|payroll"),
    ("hardware", r"laptop|desktop|printer|screen|dock|keyboard|battery|device"),
]
TEAM_BY_CATEGORY = {
    "security": "Security",
    "network": "Network",
    "email": "Microsoft 365",
    "backup": "Infrastructure",
    "access": "Service Desk",
    "erp": "Applications",
    "hardware": "Field Services",
    "general": "Service Desk",
}
SLA_MINUTES = {"P1": 60, "P2": 240, "P3": 480, "P4": 1440}
IMPACT_WEIGHT = {"company": 4, "site": 3, "team": 2, "single": 1}
URGENCY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def classify(subject: str, description: str) -> str:
    blob = f"{subject} {description}".lower()
    for category, pattern in CATEGORY_RULES:
        if re.search(pattern, blob):
            return category
    return "general"


def score_priority(impact: str, urgency: str) -> Priority:
    score = IMPACT_WEIGHT.get(impact.lower(), 1) + URGENCY_WEIGHT.get(urgency.lower(), 1)
    if score >= 8:
        return Priority.P1
    if score >= 6:
        return Priority.P2
    if score >= 4:
        return Priority.P3
    return Priority.P4


def triage(ticket: Ticket, now: datetime | None = None) -> TriageResult:
    now = now or datetime.now(timezone.utc)
    category = classify(ticket.subject, ticket.description)
    priority = score_priority(ticket.impact, ticket.urgency).value
    team = TEAM_BY_CATEGORY.get(category, "Service Desk")
    sla = SLA_MINUTES[priority]
    due = ticket.created_at + timedelta(minutes=sla)
    breached = now > due
    reason = f"{ticket.impact}/{ticket.urgency} -> {priority}; {category} -> {team}; {sla}m SLA"
    ticket.category, ticket.priority, ticket.team = category, priority, team
    ticket.sla_minutes, ticket.due_at = sla, due
    return TriageResult(
        ticket_id=ticket.ticket_id,
        category=category,
        priority=priority,
        team=team,
        sla_minutes=sla,
        due_at=due,
        breached=breached,
        reason=reason,
    )


def breach_summary(tickets: list[Ticket], now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    summary = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for ticket in tickets:
        if not ticket.priority:
            triage(ticket, now)
        if ticket.due_at and now > ticket.due_at:
            summary[ticket.priority] = summary.get(ticket.priority, 0) + 1
    return summary
