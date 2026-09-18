"""Combined persistence scanner with detection and evidence enrichment."""

from typing import Any

from app.discovery.cron import discover_cron_locations
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.timers import discover_systemd_timers
from app.discovery.users import discover_user_accounts

from app.detection.risk import calculate_risk_score
from app.detection.confidence import calculate_confidence
from app.detection.correlation import correlate_findings

from app.evidence.hash import calculate_sha256
from app.evidence.metadata import collect_file_metadata
from app.evidence.record import build_evidence_record


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = []

    for finding in findings:
        result = dict(finding)

        if "type" not in result:
            result["type"] = "account"

        if "path" not in result:
            result["path"] = result.get("username") or result.get("home") or "N/A"

        risk_data = calculate_risk_score(result)
        confidence_data = calculate_confidence(risk_data)

        result.update(confidence_data)

        file_path = result.get("path")

        if (
            file_path
            and result.get("type") == "file"
        ):
            try:
                result["evidence"] = build_evidence_record(
                    file_path,
                    calculate_sha256(file_path),
                    collect_file_metadata(file_path),
                )
            except (OSError, PermissionError) as error:
                result["evidence_error"] = str(error)

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

    findings = {
        category: enrich_findings(items)
        for category, items in raw_results.items()
    }

    correlation = correlate_findings(findings)

    return {
        "findings": findings,
        "correlation": correlation,
    }
