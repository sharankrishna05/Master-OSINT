from __future__ import annotations
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class EngineConfig(BaseModel):
    enabled: bool = True
    rate_limit: float = 1.0  # requests per second
    concurrency_cap: int = 2
    timeout: float = 10.0
    api_key: Optional[str] = None
    custom_endpoint: Optional[str] = None

class DorkForgeConfig(BaseModel):
    version: str = "1.0.0"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    default_engines: list[str] = Field(default_factory=lambda: ["google", "duckduckgo", "bing", "brave"])
    engines: Dict[str, EngineConfig] = Field(default_factory=lambda: {
        "google": EngineConfig(rate_limit=1.5, concurrency_cap=2),
        "bing": EngineConfig(rate_limit=1.2, concurrency_cap=2),
        "duckduckgo": EngineConfig(rate_limit=1.0, concurrency_cap=3),
        "brave": EngineConfig(rate_limit=1.0, concurrency_cap=2),
        "yandex": EngineConfig(rate_limit=1.0, concurrency_cap=1),
        "serpapi": EngineConfig(enabled=False, rate_limit=3.0, concurrency_cap=5),
        "google_custom_search": EngineConfig(enabled=False, rate_limit=2.0, concurrency_cap=3),
        "bing_api": EngineConfig(enabled=False, rate_limit=3.0, concurrency_cap=5)
    })
    output_directory: str = str(Path.home() / ".dorkforge" / "reports")
    enable_audit_log: bool = True

def get_config_dir() -> Path:
    config_dir = Path.home() / ".config" / "dorkforge"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir

def get_config_path() -> Path:
    return get_config_dir() / "config.yaml"

def load_config() -> DorkForgeConfig:
    cfg_path = get_config_path()
    if cfg_path.exists():
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return DorkForgeConfig(**data)
        except Exception:
            pass

    # Create default config if not present
    default_cfg = DorkForgeConfig()
    save_config(default_cfg)
    return default_cfg

def save_config(config: DorkForgeConfig):
    cfg_path = get_config_path()
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.dump(config.model_dump(), f, default_flow_style=False)
