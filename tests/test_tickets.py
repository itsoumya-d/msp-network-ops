from datetime import datetime, timedelta, timezone

from mspops.models import Ticket
from mspops.tickets import breach_summary, classify, score_priority, triage


def test_classifies_network_and_security():
    assert classify("VPN down", "site cannot reach files") == "network"
    assert classify("Suspicious MFA prompt", "repeated login prompts") == "security"
    assert classify("Mailbox full", "cannot send email") == "email"


def test_priority_matrix():
    assert score_priority("company", "critical").value == "P1"
    assert score_priority("single", "low").value == "P4"


def test_triage_sets_sla_and_team():
    ticket = Ticket("T1", "VPN down", "site outage", "Kauri", "site", "critical",
                    created_at=datetime(2026, 11, 5, tzinfo=timezone.utc))
    result = triage(ticket, now=datetime(2026, 11, 5, 0, 30, tzinfo=timezone.utc))
    assert result.category == "network"
    assert result.priority == "P2"
    assert result.team == "Network"
    assert result.sla_minutes == 240
    assert result.breached is False


def test_breach_summary():
    old = datetime.now(timezone.utc) - timedelta(hours=10)
    ticket = Ticket("T2", "VPN down", "site outage", "Kauri", "site", "critical", created_at=old)
    triage(ticket)
    assert breach_summary([ticket])["P2"] == 1
