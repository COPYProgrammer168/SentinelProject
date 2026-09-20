"""Configuration management for Sentinel."""

from __future__ import annotations
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict


_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class SentinelConfig:
    # Database
    db_path: str = str(_PROJECT_ROOT / "sentinel.db")

    # Intervals (in seconds)
    poll_interval_seconds: float = 5.0
    snapshot_interval_seconds: float = 300.0  # 5 minutes

    # Learning mode
    learning_mode_enabled: bool = True
    learning_mode_days: float = 7.0

    # Idle detection
    idle_threshold_seconds: float = 300.0  # 5 minutes of no input
    idle_network_alert_enabled: bool = True

    # Process priority
    low_process_priority: bool = True

    # Alerts & Notifications
    notification_enabled: bool = True
    notification_cooldown_seconds: float = 60.0  # cooldown per alert key
    notification_cooldown_minutes: int = 30  # cooldown for alert deduplication

    # Storage settings
    log_all_network_events: bool = True
    max_network_history_days: int = 30

    @classmethod
    def load(cls, config_file: str | Path | None = None) -> SentinelConfig:
        """Load configuration from a JSON file, environment, or defaults."""
        config = cls()
        if config_file:
            path = Path(config_file)
            if not path.is_absolute():
                path = _PROJECT_ROOT / path
        else:
            path = _PROJECT_ROOT / "sentinel_config.json"

        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(config, k):
                        setattr(config, k, v)
            except Exception as e:
                print(f"[WARN] Failed to load config from {path}: {e}. Using defaults.")

        # Environment variable overrides
        if "SENTINEL_DB_PATH" in os.environ:
            config.db_path = os.environ["SENTINEL_DB_PATH"]
        if "SENTINEL_POLL_INTERVAL" in os.environ:
            try:
                config.poll_interval_seconds = float(os.environ["SENTINEL_POLL_INTERVAL"])
            except ValueError:
                pass

        # Ensure db_path is absolute
        dp = Path(config.db_path)
        if not dp.is_absolute():
            config.db_path = str(_PROJECT_ROOT / dp)

        return config

    def save(self, config_file: str | Path = "sentinel_config.json") -> None:
        """Save configuration to a JSON file."""
        path = Path(config_file)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
