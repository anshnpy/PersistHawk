"""Linux user account discovery module."""

from pathlib import Path


PASSWD_PATH = Path("/etc/passwd")


def discover_user_accounts() -> list[dict[str, str]]:
    """Discover local Linux user accounts."""
    findings = []

    if not PASSWD_PATH.exists():
        return findings

    for line in PASSWD_PATH.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        if not line or line.startswith("#"):
            continue

        fields = line.split(":")

        if len(fields) >= 7:
            findings.append(
                {
                    "username": fields[0],
                    "uid": fields[2],
                    "home": fields[5],
                    "shell": fields[6],
                }
            )

    return findings
