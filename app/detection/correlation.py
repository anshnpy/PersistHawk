"""Finding correlation engine."""

from collections import Counter
from typing import Any


def correlate_findings(findings: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    all_findings = [
        finding
        for category_findings in findings.values()
        for finding in category_findings
    ]

    severity_counts = Counter(
        finding.get("severity", "UNKNOWN")
        for finding in all_findings
    )

    confidence_counts = Counter(
        finding.get("confidence", "UNKNOWN")
        for finding in all_findings
    )

    correlated = []

    for finding in all_findings:
        score = finding.get("risk_score", 0)
        confidence = finding.get("confidence_score", 0)

        if score >= 20 and confidence >= 60:
            correlated.append(
                {
                    "path": finding.get("path", ""),
                    "type": finding.get("type", ""),
                    "severity": finding.get("severity", "UNKNOWN"),
                    "confidence": finding.get("confidence", "UNKNOWN"),
                    "risk_score": score,
                    "confidence_score": confidence,
                    "reason": "Risk and confidence indicators overlap.",
                }
            )

    return {
        "total_findings": len(all_findings),
        "severity_counts": dict(severity_counts),
        "confidence_counts": dict(confidence_counts),
        "correlated_findings": correlated,
    }
