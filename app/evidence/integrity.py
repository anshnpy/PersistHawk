"""Evidence integrity verification module."""

from pathlib import Path
from app.evidence.hash import calculate_sha256


def verify_file_integrity(
    file_path: str,
    expected_sha256: str,
) -> dict[str, str | bool]:
    path = Path(file_path)

    if not path.is_file():
        return {
            "path": str(path),
            "status": "unavailable",
            "integrity_match": False,
        }

    current_hash = calculate_sha256(file_path)["sha256"]

    return {
        "path": str(path),
        "expected_sha256": expected_sha256,
        "current_sha256": current_hash,
        "integrity_match": current_hash == expected_sha256,
        "status": "verified",
    }
