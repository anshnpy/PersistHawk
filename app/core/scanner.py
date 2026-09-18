"""Combined persistence scanner with risk scoring."""

from typing import Any

from app.discovery.cron import discover_cron_locations
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.timers import discover_systemd_timers
from app.discovery.users import discover_user_accounts
from app.detection.risk import calculate_risk_score


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [calculate_risk_score(finding) for finding in findings]


def run_combined_scan() -> dict[str, Any]:
    raw_results = {
        "users": discover_user_accounts(),
        "ssh": discover_ssh_locations(),
        "shell_startup": discover_shell_startup_files(),
        "systemd": discover_systemd_locations(),
        "cron": discover_cron_locations(),
        "timers": discover_systemd_timers(),
    }

    return {
        category: enrich_findings(findings)
        for category, findings in raw_results.items()
    }
