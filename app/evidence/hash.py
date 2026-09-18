"""Evidence file hashing module."""

import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> dict[str, str]:
    path = Path(file_path)

    if not path.is_file():
        return {
            "path": str(path),
            "status": "unavailable",
            "sha256": "",
        }

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return {
        "path": str(path),
        "status": "hashed",
        "sha256": sha256.hexdigest(),
    }
