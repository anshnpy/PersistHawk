"""PersistHawk CLI entry point."""

import argparse

from app.core.config import settings
from app.core.logger import setup_logging
from app.discovery.cron import discover_cron_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations


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

    parser.add_argument(
        "--scan-ssh",
        action="store_true",
        help="Discover SSH persistence locations.",
    )

    parser.add_argument(
        "--scan-shell",
        action="store_true",
        help="Discover shell startup persistence files.",
    )

    parser.add_argument(
        "--scan-systemd",
        action="store_true",
        help="Discover systemd persistence locations.",
    )

    parser.add_argument(
        "--scan-cron",
        action="store_true",
        help="Discover cron persistence locations.",
    )

    parser.add_argument(
        "--log-level",
        default=settings.log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging level.",
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    print(f"{settings.app_name} {settings.version}")
    print("Core foundation initialized.")

    if args.scan_ssh:
        print("\nSSH Persistence Locations:")

        for finding in discover_ssh_locations():
            print(
                f"- {finding['path']} "
                f"({finding['type']})"
            )

    if args.scan_shell:
        print("\nShell Startup Persistence Files:")

        for finding in discover_shell_startup_files():
            print(
                f"- {finding['path']} "
                f"({finding['type']})"
            )

    if args.scan_systemd:
        print("\nSystemd Persistence Locations:")

        for finding in discover_systemd_locations():
            print(
                f"- {finding['path']} "
                f"({finding['type']})"
            )

    if args.scan_cron:
        print("\nCron Persistence Locations:")

        for finding in discover_cron_locations():
            print(
                f"- {finding['path']} "
                f"({finding['type']})"
            )


if __name__ == "__main__":
    main()
