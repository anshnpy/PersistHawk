"""Systemd timer metadata analysis module."""

from pathlib import Path


METADATA_KEYS = {
    "OnCalendar",
    "OnBootSec",
    "OnStartupSec",
    "OnActiveSec",
    "OnUnitActiveSec",
    "OnUnitInactiveSec",
    "Unit",
    "Persistent",
}


def analyze_timer_metadata(timer_path: str) -> dict[str, object]:
    path = Path(timer_path)

    result: dict[str, object] = {
        "path": str(path),
        "metadata": {},
        "status": "readable",
    }

    if not path.is_file():
        result["status"] = "missing"
        return result

    metadata: dict[str, list[str]] = {}

    for line in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)

        if key in METADATA_KEYS:
            metadata.setdefault(key, []).append(value.strip())

    result["metadata"] = metadata
    return result
