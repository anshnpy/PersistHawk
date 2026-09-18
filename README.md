# PersistHawk

Linux Persistence & LOLBin Hunter.

## Goals

- Detect suspicious persistence mechanisms.
- Analyze cron jobs and systemd services.
- Generate structured security findings.
- Support defensive security investigations.

## Status

Functional local security tool with CLI and web interface.

## Web UI

PersistHawk includes a lightweight local web interface for viewing scan findings and investigating individual results.

Start the local server:

```bash
uvicorn web.server:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`

The web interface provides:

- Security scan execution
- Findings table
- Severity filtering
- Finding search
- Risk overview
- Investigation details
- Confidence and integrity information

The interface runs locally and uses the existing PersistHawk detection and investigation engine.

## Testing

Run the test suite:

```bash
pytest -q
```

Audit Python packages:

```bash
pip-audit
```
