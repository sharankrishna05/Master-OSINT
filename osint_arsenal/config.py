from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def _csv(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    host: str = os.getenv("ARSENAL_HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT") or os.getenv("ARSENAL_PORT", "8080"))
    data_root: str = os.getenv("ARSENAL_DATA_DIR", ".")
    db_path: str = os.getenv("ARSENAL_DB") or str(Path(os.getenv("ARSENAL_DATA_DIR", ".")) / "arsenal.db")
    plugins_dir: str = os.getenv("ARSENAL_PLUGINS", "plugins")
    default_keys: list[str] = field(default_factory=lambda: _csv("ARSENAL_DEFAULT_KEYS", ""))

    rate_limit: int = int(os.getenv("ARSENAL_RATE_LIMIT", "60"))
    rate_window: int = int(os.getenv("ARSENAL_RATE_WINDOW", "60"))
    http_timeout: float = float(os.getenv("ARSENAL_TIMEOUT", "10"))
    concurrency: int = int(os.getenv("ARSENAL_CONCURRENCY", "25"))
    cache_ttl: int = int(os.getenv("ARSENAL_CACHE_TTL", "600"))
    cors_origin: str = os.getenv("ARSENAL_CORS", "*")
    user_agent: str = os.getenv("ARSENAL_UA",
                                "Mozilla/5.0 (compatible; OsintArsenal/0.2)")

    max_followups: int = int(os.getenv("ARSENAL_MAX_FOLLOWUPS", "3"))
    followup_depth: int = int(os.getenv("ARSENAL_FOLLOWUP_DEPTH", "2"))
    disable_followups: bool = os.getenv("ARSENAL_NO_FOLLOWUP", "0") == "1"

    data_dir: Path = field(
        default_factory=lambda: Path(__file__).parent / "data"
    )


settings = Settings()
