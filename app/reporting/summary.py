from __future__ import annotations

import json
from pathlib import Path


def print_report_summary(report_path: str = "data/report.json") -> None:
    path = Path(report_path)

    if not path.exists():
        print(f"[ERROR] Report not found: {path}")
        return

    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    report = data["report"]
    findings = report["findings"]
    correlation = report["correlation"]

    print("\n" + "=" * 60)
    print("              PERSISTHAWK ANALYST SUMMARY")
    print("=" * 60)

    print(f"Status          : {report.get('status', 'unknown')}")
    print(f"Total Findings  : {correlation['total_findings']}")

    print("\n[SEVERITY BREAKDOWN]")
    for severity, count in correlation["severity_counts"].items():
        print(f"  {severity:<12}: {count}")

    print("\n[CONFIDENCE BREAKDOWN]")
    for confidence, count in correlation["confidence_counts"].items():
        print(f"  {confidence:<12}: {count}")

    print("\n[FINDINGS BY CATEGORY]")
    for category, items in findings.items():
        print(f"  {category:<16}: {len(items)}")

    correlated = correlation.get("correlated_findings", [])

    print("\n[CORRELATED FINDINGS]")
    print(f"  Total           : {len(correlated)}")

    if correlated:
        for item in correlated[:10]:
            print(
                f"  - {item.get('path', 'N/A')} "
                f"(Risk: {item.get('risk_score', 'N/A')})"
            )

    print("=" * 60 + "\n")


if __name__ == "__main__":
    print_report_summary()
