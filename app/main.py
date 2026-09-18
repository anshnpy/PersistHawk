"""PersistHawk CLI entry point."""

import argparse

from app.core.config import settings
from app.core.logger import setup_logging
from app.core.report import export_json_report, export_evidence_report
from app.core.scanner import run_combined_scan
from app.discovery.cron import discover_cron_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.timers import discover_systemd_timers
from app.discovery.timer_metadata import analyze_timer_metadata
from app.discovery.timer_detector import detect_suspicious_timer
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations
from app.discovery.users import discover_user_accounts
from app.investigation.inspect import investigate_finding


def main() -> None:
    parser = argparse.ArgumentParser(
        prog=settings.app_name,
        description="Linux persistence detection and investigation toolkit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {settings.version}",
    )

    parser.add_argument("--scan-users", action="store_true")
    parser.add_argument("--scan-ssh", action="store_true")
    parser.add_argument("--scan-shell", action="store_true")
    parser.add_argument("--scan-systemd", action="store_true")
    parser.add_argument("--scan-cron", action="store_true")
    parser.add_argument("--scan-timers", action="store_true")

    parser.add_argument(
        "--export-report",
        metavar="PATH",
        nargs="?",
        const="data/report.json",
        help="Export a JSON report.",
    )

    parser.add_argument(
        "--analyze-timer",
        metavar="PATH",
        help="Analyze metadata of a systemd timer file.",
    )

    parser.add_argument(
        "--detect-timer",
        metavar="PATH",
        help="Detect review flags in a systemd timer.",
    )
    parser.add_argument(
        "--investigate",
        metavar="PATH",
        help="Investigate a finding by evidence path.",
    )

    parser.add_argument(
        "--log-level",
        default=settings.log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    print(f"{settings.app_name} {settings.version}")
    print("Core foundation initialized.")

    if args.scan_users:
        print("\nLocal User Accounts:")
        for finding in discover_user_accounts():
            print(
                f"- {finding['username']} "
                f"(UID: {finding['uid']}, "
                f"Shell: {finding['shell']})"
            )

    if args.scan_ssh:
        print("\nSSH Persistence Locations:")
        for finding in discover_ssh_locations():
            print(f"- {finding['path']} ({finding['type']})")

    if args.scan_shell:
        print("\nShell Startup Persistence Files:")
        for finding in discover_shell_startup_files():
            print(f"- {finding['path']} ({finding['type']})")

    if args.scan_systemd:
        print("\nSystemd Persistence Locations:")
        for finding in discover_systemd_locations():
            print(f"- {finding['path']} ({finding['type']})")

    if args.scan_cron:
        print("\nCron Persistence Locations:")
        for finding in discover_cron_locations():
            print(f"- {finding['path']} ({finding['type']})")

    if args.scan_timers:
        print("\nSystemd Timer Persistence Locations:")
        for finding in discover_systemd_timers():
            print(f"- {finding['path']} ({finding['type']})")

    if args.analyze_timer:
        analysis = analyze_timer_metadata(args.analyze_timer)
        print("\nTimer Metadata Analysis:")
        print(f"Path: {analysis['path']}")
        print(f"Status: {analysis['status']}")
        print(f"Metadata: {analysis['metadata']}")

    if args.detect_timer:
        analysis = analyze_timer_metadata(args.detect_timer)
        detection = detect_suspicious_timer(analysis)

        print("\nTimer Detection Results:")
        print(f"Path: {detection['path']}")
        print(f"Status: {detection['status']}")
        print(f"Flag Count: {detection['flag_count']}")

        for flag in detection["flags"]:
            print(
                f"- [{flag['severity']}] "
                f"{flag['reason']}"
            )

    if args.investigate:
        scan_results = run_combined_scan()
        selected = None

        for category, items in scan_results["findings"].items():
            for item in items:
                if item.get("path") == args.investigate:
                    selected = dict(item)
                    selected["category"] = category
                    break
            if selected:
                break

        print("\nInvestigation Results:")

        if not selected:
            print(f"Finding not found: {args.investigate}")
        else:
            result = investigate_finding(selected)
            print(f"Category: {result['category']}")
            print(f"Type: {result['type']}")
            print(f"Path: {result['path']}")
            print(f"Severity: {result['severity']}")
            print(f"Risk: {result['risk_score']}")
            print(f"Confidence: {result['confidence_score']}")
            print(
                f"Integrity: "
                f"{result['integrity'].get('integrity_match', False)}"
            )

    if args.export_report:
        scan_results = run_combined_scan()

        output = export_json_report(
            {
                "status": "completed",
                **scan_results,
            },
            args.export_report,
        )
        evidence_output = export_evidence_report(
            {
                "status": "completed",
                **scan_results,
            }
        )

        print(f"\nJSON report exported: {output}")
        print(f"Evidence report exported: {evidence_output}")


if __name__ == "__main__":
    main()
