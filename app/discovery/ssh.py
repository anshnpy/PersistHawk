"""SSH persistence discovery module."""

from pathlib import Path


SSH_PATHS = [
    Path.home() / ".ssh/authorized_keys",
    Path.home() / ".ssh/config",
    Path("/etc/ssh/sshd_config"),
    Path("/etc/ssh/ssh_config"),
]


def discover_ssh_locations() -> list[dict[str, str]]:
    """Discover SSH-related persistence locations."""
    findings = []

    for path in SSH_PATHS:
        if path.exists():
            findings.append(
                {
                    "path": str(path),
                    "type": "file",
                    "status": "present",
                }
            )

    return findings
