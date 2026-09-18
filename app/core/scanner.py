"""Combined persistence scanner."""

from typing import Any

from app.discovery.cron import discover_cron_locations
from app.discovery.shell_startup import discover_shell_startup_files
from app.discovery.ssh import discover_ssh_locations
from app.discovery.systemd import discover_systemd_locations
from app.discovery.timers import discover_systemd_timers
from app.discovery.users import discover_user_accounts


def run_combined_scan() -> dict[str, Any]:
    return {
        "users": discover_user_accounts(),
        "ssh": discover_ssh_locations(),
        "shell_startup": discover_shell_startup_files(),
        "systemd": discover_systemd_locations(),
        "cron": discover_cron_locations(),
        "timers": discover_systemd_timers(),
    }
