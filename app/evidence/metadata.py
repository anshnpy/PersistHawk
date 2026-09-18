"""Evidence file metadata collection module."""

import os
import stat
from pathlib import Path
from typing import Any


def collect_file_metadata(file_path: str) -> dict[str, Any]:
    path = Path(file_path)

    if not path.is_file():
        return {
            "path": str(path),
            "status": "unavailable",
        }

    try:
        file_stat = path.stat()

        return {
            "path": str(path),
            "status": "collected",
            "size_bytes": file_stat.st_size,
            "mode": stat.filemode(file_stat.st_mode),
            "uid": file_stat.st_uid,
            "gid": file_stat.st_gid,
            "modified_at": file_stat.st_mtime,
        }

    except OSError as error:
        return {
            "path": str(path),
            "status": "error",
            "error": str(error),
        }
