from __future__ import annotations

import json
from pathlib import Path


SEVERITY_ORDER = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}


def show_interesting_findings(report_path: str = "data/report.json") -> None:
    path = Path(report_path)

    if not path.exists():
        print(f"[ERROR] Report not found: {path}")
        return

    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    report = data["report"]
    findings_by_category = report["findings"]

    findings = []

    for category, items in findings_by_category.items():
        for item in items:
            enriched = dict(item)
            enriched["category"] = category
            findings.append(enriched)

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity", "LOW"), 99),
            -item.get("risk_score", 0),
            -item.get("confidence_score", 0),
        )
    )

    interesting = [
        item
        for item in findings
        if item.get("severity") in {"HIGH", "MEDIUM"}
        or item.get("risk_score", 0) >= 10
    ]

    print("\n" + "=" * 72)
    print("                 PERSISTHAWK INTERESTING FINDINGS")
    print("=" * 72)

    print(f"Total findings     : {len(findings)}")
    print(f"Interesting findings: {len(interesting)}")

    if not interesting:
        print("\nNo findings currently meet the analyst-interest threshold.")
        print("=" * 72 + "\n")
        return

    for index, item in enumerate(interesting, start=1):
        print(f"\n[{index}] {item.get('severity', 'UNKNOWN')} | {item.get('category', 'unknown')}")
        print(f"    Risk       : {item.get('risk_score', 0)}")
        print(f"    Confidence : {item.get('confidence_score', 0)} ({item.get('confidence', 'UNKNOWN')})")
        print(f"    Type       : {item.get('type', 'unknown')}")
        print(f"    Path       : {item.get('path', 'N/A')}")

        evidence = item.get("evidence", {})
        if evidence:
            print("    Evidence:")
            print(f"      SHA256   : {evidence.get('hash', {}).get('sha256', 'N/A')}")

            metadata = evidence.get("metadata", {})
            if metadata:
                print(f"      Size     : {metadata.get('size', 'N/A')} bytes")
                print(f"      Mode     : {metadata.get('mode', 'N/A')}")
                print(f"      UID      : {metadata.get('uid', 'N/A')}")
                print(f"      GID      : {metadata.get('gid', 'N/A')}")
                print(f"      Modified : {metadata.get('modified', 'N/A')}")

        reasons = item.get("risk_reasons", [])
        confidence_reasons = item.get("confidence_reasons", [])

        if reasons:
            print("    Risk reasons:")
            for reason in reasons:
                print(f"      - {reason}")

        if confidence_reasons:
            print("    Confidence reasons:")
            for reason in confidence_reasons:
                print(f"      - {reason}")

    print("\n" + "=" * 72 + "\n")


if __name__ == "__main__":
    show_interesting_findings()
