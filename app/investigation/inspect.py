from typing import Any


def flatten_findings(findings_by_category: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Flatten findings and assign stable numeric IDs."""
    flattened = []

    for category, items in findings_by_category.items():
        for item in items:
            finding = dict(item)
            finding["category"] = category
            finding["finding_id"] = len(flattened) + 1
            flattened.append(finding)

    return flattened


def investigate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return investigation details for a finding."""
    evidence = finding.get("evidence") or {}
    integrity = evidence.get("integrity")

    return {
        "finding_id": finding.get("finding_id"),
        "category": finding.get("category"),
        "type": finding.get("type"),
        "path": finding.get("path"),
        "severity": finding.get("severity"),
        "risk_score": finding.get("risk_score", 0),
        "confidence_score": finding.get("confidence_score", 0),
        "evidence": evidence,
        "integrity": integrity,
    }
