"""Analyst investigation workflow."""

from typing import Any

from app.evidence.integrity import verify_file_integrity


def investigate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    result = {
        "category": finding.get("category", "unknown"),
        "type": finding.get("type", "unknown"),
        "path": finding.get("path"),
        "severity": finding.get("severity"),
        "risk_score": finding.get("risk_score", 0),
        "confidence_score": finding.get("confidence_score", 0),
        "status": "review_required",
    }

    evidence = finding.get("evidence", {})
    metadata = evidence.get("metadata", {})
    expected_hash = evidence.get("hash", {}).get("sha256")

    result["evidence"] = evidence

    if result["path"] and expected_hash:
        result["integrity"] = verify_file_integrity(
            result["path"],
            expected_hash,
        )
    else:
        result["integrity"] = {
            "status": "unavailable",
            "integrity_match": False,
        }

    return result
