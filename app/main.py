import argparse

from app.core.config import settings
from app.core.logger import setup_logging


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
        "--log-level",
        default=settings.log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging level.",
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    print(f"{settings.app_name} {settings.version}")
    print("Core foundation initialized.")


if __name__ == "__main__":
    main()
