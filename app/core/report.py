"""JSON report export module."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def export_json_report(
    report_data: dict[str, Any],
    output_path: str = "data/report.json",
) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "PersistHawk",
        "report": report_data,
    }

    path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return str(path)


def export_evidence_report(
    report_data: dict[str, Any],
    output_path: str = "data/evidence_report.json",
) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    evidence_records = []

    for category, items in report_data.get("findings", {}).items():
        for item in items:
            evidence = item.get("evidence")

            if evidence:
                evidence_records.append({
                    "category": category,
                    "severity": item.get("severity"),
                    "risk_score": item.get("risk_score"),
                    "confidence_score": item.get("confidence_score"),
                    "evidence": evidence,
                })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "PersistHawk",
        "evidence_count": len(evidence_records),
        "evidence": evidence_records,
    }

    path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return str(path)
