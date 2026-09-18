"""Combined persistence scanner with risk scoring."""

from typing import Any

from app.discovery.cron import discover_cron_locations
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.timers import discover_systemd_timers
from app.discovery.users import discover_user_accounts
from app.detection.risk import calculate_risk_score
from app.detection.confidence import calculate_confidence
from app.evidence.hash import calculate_sha256


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = []

    for finding in findings:
        result = calculate_confidence(calculate_risk_score(finding))

        if finding.get("type") == "file" and finding.get("path"):
            result["evidence"] = calculate_sha256(finding["path"])

        enriched.append(result)

    return enriched


def run_combined_scan() -> dict[str, Any]:
    raw_results = {
        "users": discover_user_accounts(),
        "ssh": discover_ssh_locations(),
        "shell_startup": discover_shell_startup_files(),
        "systemd": discover_systemd_locations(),
        "cron": discover_cron_locations(),
        "timers": discover_systemd_timers(),
    }

    enriched_results = {
        category: enrich_findings(findings)
        for category, findings in raw_results.items()
    }

    enriched_results["correlation"] = correlate_findings(enriched_results)

    return enriched_results
