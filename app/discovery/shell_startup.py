"""Shell startup persistence discovery module."""

from pathlib import Path


STARTUP_FILES = [
    Path.home() / ".bashrc",
    Path.home() / ".bash_profile",
    Path.home() / ".profile",
    Path.home() / ".zshrc",
]


def discover_shell_startup_files() -> list[dict[str, str]]:
    """Discover shell startup files."""
    findings = []

    for path in STARTUP_FILES:
        if path.exists():
            findings.append(
                {
                    "path": str(path),
                    "type": "file",
                    "status": "present",
                }
            )

    return findings
