"""Systemd timer persistence discovery module."""

from pathlib import Path


SYSTEMD_TIMER_PATHS = [
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
    Path.home() / ".config/systemd/user",
]


def discover_systemd_timers() -> list[dict[str, str]]:
    findings = []
    seen_paths = set()

    for base_path in SYSTEMD_TIMER_PATHS:
        if not base_path.exists() or not base_path.is_dir():
            continue

        for timer_path in sorted(base_path.glob("*.timer")):
            resolved_path = timer_path.resolve()

            if resolved_path in seen_paths:
                continue

            seen_paths.add(resolved_path)

            findings.append(
                {
                    "path": str(resolved_path),
                    "type": "systemd-timer",
                    "status": "present",
                }
            )

    return findings
