"""PersistHawk CLI entry point."""

import argparse

from app.core.config import settings
from app.core.logger import setup_logging
from app.discovery.cron import discover_cron_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.timers import discover_systemd_timers
from app.discovery.timer_metadata import analyze_timer_metadata
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations
from app.discovery.users import discover_user_accounts


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
        "--analyze-timer",
        metavar="PATH",
        help="Analyze metadata of a systemd timer file.",
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


if __name__ == "__main__":
    main()
