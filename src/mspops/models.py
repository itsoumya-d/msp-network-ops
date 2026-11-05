from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum


class Priority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


@dataclass
class Ticket:
    ticket_id: str
    subject: str
    description: str
    client: str
    impact: str
    urgency: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    category: str = ""
    priority: str = ""
    team: str = ""
    sla_minutes: int = 0
    due_at: datetime | None = None


@dataclass
class Asset:
    asset_id: str
    client: str
    kind: str
    model: str
    warranty_end: str
    eol_date: str
    backup_enabled: bool
    last_seen_days: int


@dataclass
class Event:
    event_id: str
    site: str
    device: str
    state: str
    severity: str = "high"
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TriageResult:
    ticket_id: str
    category: str
    priority: str
    team: str
    sla_minutes: int
    due_at: datetime
    breached: bool
    reason: str
