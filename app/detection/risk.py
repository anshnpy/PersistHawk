"""Risk scoring engine for PersistHawk."""

from typing import Any


def calculate_risk_score(finding: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    finding_type = finding.get("type", "").lower()
    path = finding.get("path", "").lower()

    if finding_type == "systemd-timer":
        score += 10
        reasons.append("Systemd timer persistence location detected.")

    if "authorized_keys" in path:
        score += 20
        reasons.append("SSH authorized keys location detected.")

    if "cron" in path:
        score += 10
        reasons.append("Cron persistence location detected.")

    if ".config" in path:
        score += 5
        reasons.append("User-level configuration location detected.")

    if score >= 40:
        severity = "HIGH"
    elif score >= 20:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        **finding,
        "risk_score": score,
        "severity": severity,
        "risk_reasons": reasons,
    }
