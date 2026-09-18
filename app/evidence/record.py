"""Unified evidence record builder."""

from typing import Any


def build_evidence_record(
    file_path: str,
    hash_data: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "path": file_path,
        "hash": hash_data,
        "metadata": metadata,
    }
