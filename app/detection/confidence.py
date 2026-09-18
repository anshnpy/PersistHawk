"""Heuristic confidence scoring for PersistHawk findings."""

from typing import Any


def calculate_confidence(finding: dict[str, Any]) -> dict[str, Any]:
    score = 50
    reasons: list[str] = []

    path = finding.get("path", "").lower()
    finding_type = finding.get("type", "").lower()

    if finding_type == "systemd-timer":
        score += 10
        reasons.append("Systemd timer requires review.")

    if "authorized_keys" in path:
        score += 15
        reasons.append("SSH key persistence location requires review.")

    if "/tmp/" in path or "/var/tmp/" in path:
        score += 20
        reasons.append("Temporary directory requires investigation.")

    if "/." in path:
        score += 5
        reasons.append("Hidden configuration path detected.")

    score = min(score, 100)

    if score >= 80:
        confidence = "HIGH"
    elif score >= 60:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        **finding,
        "confidence_score": score,
        "confidence": confidence,
        "confidence_reasons": reasons,
    }
