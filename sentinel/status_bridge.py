"""Status bridge for Sentinel.

Writes the current ambient severity to a small file so external tools
such as a Windhawk mod can reflect it in the Windows shell.

File location: C:\ProgramData\Sentinel\status.txt
Contents: one of NORMAL, WARNING, CRITICAL
"""

from __future__ import annotations
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    from sentinel.db.storage import Storage
except Exception:
    Storage = None  # type: ignore[misc,assignment]

_STATUS_DIR = Path(r"C:\ProgramData\Sentinel")
_STATUS_FILE = _STATUS_DIR / "status.txt"

_NORMAL = "NORMAL"
_WARNING = "WARNING"
_CRITICAL = "CRITICAL"


def _ensure_dir() -> None:
    try:
        _STATUS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _read_current_file() -> str:
    try:
        if _STATUS_FILE.is_file():
            return _STATUS_FILE.read_text(encoding="utf-8", errors="replace").strip().upper()
    except Exception:
        pass
    return ""


def _write_status(status: str) -> None:
    try:
        _ensure_dir()
        _STATUS_FILE.write_text(status + "\n", encoding="utf-8")
    except Exception:
        pass


def compute_status(db_path: Optional[str] = None) -> str:
    if Storage is None:
        return _NORMAL
    path = db_path or os.environ.get("SENTINEL_DB_PATH")
    if not path:
        try:
            from sentinel.config import SentinelConfig
            config = SentinelConfig.load()
            path = config.db_path
        except Exception:
            path = None
    if not path:
        return _NORMAL
    try:
        storage = Storage(path)
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=5)).isoformat()
        with storage._connection() as conn:
            row = conn.execute(
                """
                SELECT severity FROM alerts
                WHERE timestamp >= ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END ASC
                LIMIT 1
                """,
                (cutoff,),
            ).fetchone()
            if not row:
                return _NORMAL
            sev = (row["severity"] or "").lower()
            if sev == "critical":
                return _CRITICAL
            if sev in ("high", "medium"):
                return _WARNING
            return _NORMAL
    except Exception:
        return _NORMAL


def update_status(db_path: Optional[str] = None) -> str:
    status = compute_status(db_path)
    previous = _read_current_file()
    if previous != status:
        _write_status(status)
    return status
