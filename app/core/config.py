from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "PersistHawk"
    version: str = "0.1.0"
    log_level: str = "INFO"
    data_dir: Path = Path("data")


settings = Settings()
