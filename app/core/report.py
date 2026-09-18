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
