"""Status bridge for Sentinel.

Writes the current ambient severity to a small file so external tools
such as a Windhawk mod can reflect it in the Windows shell.

File location: C:\\ProgramData\\Sentinel\\status.txt
Contents: one of NORMAL, WARNING, CRITICAL

Also writes C:\\ProgramData\\Sentinel\\status.json with full overview data
so external tools can consume richer state without parsing HTML or
querying Flask directly.
"""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from sentinel.db.storage import Storage
except Exception:
    Storage = None  # type: ignore[misc,assignment]

_STATUS_DIR = Path(r"C:\ProgramData\Sentinel")
_STATUS_FILE = _STATUS_DIR / "status.txt"
_STATUS_JSON = _STATUS_DIR / "status.json"

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


def _write_status_json(payload: Dict[str, Any]) -> None:
    try:
        _ensure_dir()
        _STATUS_JSON.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
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


def compute_status_payload(db_path: Optional[str] = None) -> Dict[str, Any]:
    if Storage is None:
        return {"status": _NORMAL, "updated": datetime.now(timezone.utc).isoformat()}
    path = db_path or os.environ.get("SENTINEL_DB_PATH")
    if not path:
        try:
            from sentinel.config import SentinelConfig
            config = SentinelConfig.load()
            path = config.db_path
        except Exception:
            path = None
    if not path:
        return {"status": _NORMAL, "updated": datetime.now(timezone.utc).isoformat()}
    try:
        storage = Storage(path)
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=5)).isoformat()
        payload: Dict[str, Any] = {
            "status": _NORMAL,
            "updated": now.isoformat(),
            "window_minutes": 5,
        }
        with storage._connection() as conn:
            stats_row = conn.execute(
                """
                SELECT COUNT(*) as alerts_total,
                       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as alerts_critical,
                       SUM(CASE WHEN severity='log_only' THEN 1 ELSE 0 END) as alerts_log_only
                FROM alerts
                WHERE timestamp >= ?
                """,
                (cutoff,),
            ).fetchone()
            if stats_row:
                payload["alerts_total"] = stats_row["alerts_total"] or 0
                payload["alerts_critical"] = stats_row["alerts_critical"] or 0
                payload["alerts_log_only"] = stats_row["alerts_log_only"] or 0

            flagged_row = conn.execute(
                """
                SELECT COUNT(*) as flagged_total
                FROM network_events
                WHERE timestamp >= ? AND is_flagged = 1
                """,
                (cutoff,),
            ).fetchone()
            payload["flagged_network_events"] = flagged_row["flagged_total"] if flagged_row else 0

            recent = conn.execute(
                """
                SELECT timestamp, severity, alert_type, target_item, message
                FROM alerts
                WHERE timestamp >= ?
                ORDER BY id DESC
                LIMIT 20
                """,
                (cutoff,),
            ).fetchall()
            payload["recent_alerts"] = [
                {
                    "timestamp": r["timestamp"],
                    "severity": r["severity"],
                    "alert_type": r["alert_type"],
                    "target_item": r["target_item"],
                    "message": r["message"],
                }
                for r in recent
            ]
            top_row = conn.execute(
                """
                SELECT alert_type, COUNT(*) as cnt
                FROM alerts
                WHERE timestamp >= ? AND severity = 'critical'
                GROUP BY alert_type
                ORDER BY cnt DESC
                LIMIT 10
                """,
                (cutoff,),
            ).fetchall()
            payload["top_critical_alert_types"] = {r["alert_type"]: r["cnt"] for r in top_row}

        status = compute_status(db_path=path)
        payload["status"] = status
        return payload
    except Exception:
        return {"status": _NORMAL, "updated": now.isoformat()}


def update_status(db_path: Optional[str] = None) -> str:
    status = compute_status(db_path)
    previous = _read_current_file()
    if previous != status:
        _write_status(status)
    payload = compute_status_payload(db_path)
    _write_status_json(payload)
    return status
