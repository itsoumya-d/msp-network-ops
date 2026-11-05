from mspops.finops import CostRecord, ResourceMetric, budget_burn, detect_anomalies, recommendations


def test_cost_anomaly():
    records = [
        CostRecord("acct", "EC2", "2026-09", 1000.0),
        CostRecord("acct", "EC2", "2026-10", 1500.0),
        CostRecord("acct", "S3", "2026-09", 100.0),
        CostRecord("acct", "S3", "2026-10", 110.0),
    ]
    anomalies = detect_anomalies(records)
    assert len(anomalies) == 1
    assert anomalies[0]["service"] == "EC2"
    assert anomalies[0]["delta"] == 500.0


def test_recommendations():
    resources = [
        ResourceMetric("vol-1", "acct", "EBS", 0, 0, False, 40.0),
        ResourceMetric("i-1", "acct", "EC2", 3, 10, True, 200.0),
        ResourceMetric("i-2", "acct", "EC2", 8, 15, True, 100.0),
        ResourceMetric("i-3", "acct", "EC2", 45, 60, True, 100.0),
    ]
    actions = {r["resource_id"]: r["action"] for r in recommendations(resources)}
    assert actions == {"vol-1": "delete_unattached", "i-1": "stop_idle", "i-2": "rightsize_down"}


def test_budget_burn():
    records = [CostRecord("acct", "EC2", "2026-11", 800.0), CostRecord("acct", "S3", "2026-11", 300.0)]
    result = budget_burn(records, 1000.0, "2026-11")
    assert result["spend"] == 1100.0
    assert result["over_budget"] is True
    assert result["remaining"] == -100.0
