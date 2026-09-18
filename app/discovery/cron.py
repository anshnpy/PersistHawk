"""Cron persistence discovery module."""

from pathlib import Path


CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]


def discover_cron_locations() -> list[dict[str, str]]:
    """Discover existing cron persistence locations."""
    findings = []

    for path in CRON_PATHS:
        if path.exists():
            findings.append(
                {
                    "path": str(path),
                    "type": "directory" if path.is_dir() else "file",
                    "status": "present",
                }
            )

    return findings
