"""Systemd persistence discovery module."""

from pathlib import Path


SYSTEMD_PATHS = [
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
    Path.home() / ".config/systemd/user",
]


def discover_systemd_locations() -> list[dict[str, str]]:
    """Discover systemd persistence locations."""
    findings = []

    for path in SYSTEMD_PATHS:
        if path.exists():
            findings.append(
                {
                    "path": str(path),
                    "type": "directory",
                    "status": "present",
                }
            )

    return findings
