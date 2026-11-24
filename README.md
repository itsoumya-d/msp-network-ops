# msp-network-ops

[![ci](https://github.com/itsoumya-d/msp-network-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/itsoumya-d/msp-network-ops/actions/workflows/ci.yml)

A small, tested reference for the operational workflows MSPs, ISPs and
enterprise network teams run every day:

- Ticket triage and routing (network, email, security, backup, access, ERP,
  hardware).
- Priority scoring and SLA breach detection.
- Asset inventory risk: warranty expiry, end-of-life, missing backups, stale
  inventory.
- Network configuration compliance: Telnet, SSH v2, NTP, SNMPv3, backup age,
  supported firmware, default credentials.
- Site-vs-device outage triage with runbook guidance.
- Cloud cost governance: month-over-month anomaly detection, unattached/idle/
  overprovisioned resource recommendations and budget burn.
- FastAPI surface and synthetic demo data.

This is a **reference implementation**, not a claim of production RMM/PSA
experience. Integrations with live PSA, RMM or monitoring tools are not
included; the rules and API are the tested core.

## Run

```bash
uv venv --python 3.12
source .venv/bin/activate
pip install -e ".[dev]"
pytest
uvicorn mspops.api:app --reload
python -m mspops.generate
```

## Managed cloud provider use case

Built for MSP/ISP and managed-cloud workflows such as DDS IT: service-desk
triage, SLA control, asset risk, network configuration compliance, outage
triage and Datadog-style cloud cost governance.

## API

- `POST /tickets/triage`
- `POST /tickets/breaches`
- `POST /assets/risk`
- `POST /netops/compliance`
- `POST /netops/outage`
- `POST /identity/audit`
- `POST /security/posture`
- `POST /finops/anomalies`
- `POST /finops/recommendations`
- `POST /finops/budget`
- `GET /health`

## License

MIT
