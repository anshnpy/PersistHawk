"""Heuristic systemd timer detection module."""

from typing import Any


def detect_suspicious_timer(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    metadata = analysis.get("metadata", {})
    flags: list[dict[str, str]] = []

    if "OnBootSec" in metadata:
        flags.append(
            {
                "severity": "LOW",
                "reason": "Timer uses OnBootSec scheduling.",
            }
        )

    if "OnUnitActiveSec" in metadata:
        flags.append(
            {
                "severity": "LOW",
                "reason": "Timer uses recurring OnUnitActiveSec scheduling.",
            }
        )

    if "OnUnitInactiveSec" in metadata:
        flags.append(
            {
                "severity": "LOW",
                "reason": "Timer uses OnUnitInactiveSec scheduling.",
            }
        )

    if "Unit" not in metadata:
        flags.append(
            {
                "severity": "INFO",
                "reason": "No explicit Unit mapping found.",
            }
        )

    return {
        "path": analysis.get("path", ""),
        "status": analysis.get("status", "unknown"),
        "flags": flags,
        "flag_count": len(flags),
    }
