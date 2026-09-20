"""Local-only review dashboard for Sentinel.

Runs on 127.0.0.1 only.  Reads from the existing SQLite database;
does not change detection logic.
"""

from __future__ import annotations
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request

from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage

DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"
TEMPLATE_PATH = DASHBOARD_DIR / "templates" / "index.html"


def create_app(db_path: Optional[str] = None) -> Flask:
    if db_path is None:
        config = SentinelConfig.load()
        db_path = config.db_path

    storage = Storage(db_path)
    app = Flask(__name__, template_folder=str(DASHBOARD_DIR / "templates"), static_folder=str(DASHBOARD_DIR / "static"))
    app.config["SENTINEL_DB_PATH"] = db_path
    app.config["SENTINEL_STORAGE"] = storage

    def _get_storage() -> Storage:
        return app.config["SENTINEL_STORAGE"]

    @app.route("/")
    def index():
        return render_template_string((TEMPLATE_PATH).read_text(encoding="utf-8"))

    @app.route("/api/overview")
    def api_overview():
        storage = _get_storage()
        stats = storage.get_stats()
        period_stats = storage.get_period_stats()
        period_start = datetime.fromisoformat(stats.get("period_start", datetime.now(timezone.utc).isoformat()))
        now = datetime.now(timezone.utc)
        time_until_reset = max(0, int((period_start.replace(hour=0, minute=0, second=0, microsecond=0) - now).total_seconds()))
        if stats.get("period_type") == "weekly":
            days_until_monday = (7 - now.weekday()) % 7
            next_monday = now.replace(hour=0, minute=0, second=0, microsecond=0)
            next_monday = next_monday.replace(day=now.day + days_until_monday if days_until_monday > 0 else 0)
            if days_until_monday == 0:
                next_monday = now
            else:
                next_monday = now.replace(day=now.day + days_until_monday)
            time_until_reset = max(0, int((next_monday - now).total_seconds()))
        return jsonify({
            "stats": stats,
            "period_stats": period_stats,
            "time_until_reset_seconds": time_until_reset,
        })

    @app.route("/api/period_history")
    def api_period_history():
        storage = _get_storage()
        return jsonify(storage.get_period_history())

    @app.route("/api/allowlist")
    def api_allowlist():
        storage = _get_storage()
        return jsonify(storage.get_allowlist())

    @app.route("/api/network_events")
    def api_network_events():
        storage = _get_storage()
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
        flagged_only = request.args.get("flagged_only") == "1"
        process_name = request.args.get("process_name", "").strip()
        remote_ip = request.args.get("remote_ip", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()
        query = "SELECT * FROM network_events WHERE 1=1"
        params = []
        if flagged_only:
            query += " AND is_flagged = 1"
        if process_name:
            query += " AND process_name LIKE ?"
            params.append(f"%{process_name}%")
        if remote_ip:
            query += " AND remote_ip LIKE ?"
            params.append(f"%{remote_ip}%")
        if date_from:
            query += " AND timestamp >= ?"
            params.append(date_from)
        if date_to:
            query += " AND timestamp <= ?"
            params.append(date_to)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with storage._connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return jsonify([dict(r) for r in rows])

    @app.route("/api/snapshots")
    def api_snapshots():
        storage = _get_storage()
        with storage._connection() as conn:
            rows = conn.execute(
                "SELECT timestamp, COUNT(*) as item_count FROM system_snapshots GROUP BY timestamp ORDER BY timestamp DESC LIMIT 50"
            ).fetchall()
            return jsonify([dict(r) for r in rows])

    @app.route("/api/snapshots/<timestamp>")
    def api_snapshot_detail(timestamp: str):
        storage = _get_storage()
        return jsonify(storage.get_latest_system_snapshot(timestamp))

    @app.route("/api/alerts")
    def api_alerts():
        storage = _get_storage()
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
        severity = request.args.get("severity", "").strip()
        alert_type = request.args.get("alert_type", "").strip()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if alert_type:
            query += " AND alert_type LIKE ?"
            params.append(f"%{alert_type}%")
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with storage._connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return jsonify([dict(r) for r in rows])

    @app.route("/api/alerts/grouped")
    def api_alerts_grouped():
        storage = _get_storage()
        return jsonify(storage.get_grouped_alerts())

    @app.route("/api/apps")
    def api_apps():
        from sentinel.platform_utils.apps import get_running_apps, get_installed_apps
        storage = _get_storage()
        running = {a["name"].lower(): a for a in get_running_apps()}
        installed = {a["name"].lower(): a for a in get_installed_apps()}
        allow = storage.get_allowlist()
        allow_map = {a["process_name"].lower(): a for a in allow}
        merged: Dict[str, Dict[str, Any]] = {}
        for key, app in {**running, **installed}.items():
            entry = allow_map.get(key)
            app["trusted"] = entry is not None
            app["protected"] = entry is not None and bool(entry.get("is_blocked"))
            app.setdefault("status", "Running" if key in running else "Installed")
            app.setdefault("publisher", "")
            app.setdefault("executable_path", "")
            merged[key] = app
        return jsonify(list(merged.values()))

    @app.route("/api/blocklist")
    def api_blocklist():
        storage = _get_storage()
        return jsonify(storage.get_blocklist())

    @app.route("/api/snoozed")
    def api_snoozed():
        storage = _get_storage()
        return jsonify(storage.get_snoozed_alerts())

    @app.route("/api/allowlist/remove", methods=["POST"])
    def api_allowlist_remove():
        storage = _get_storage()
        data = request.get_json(force=True)
        storage.remove_allowlist_entry(data.get("process_name", ""))
        return jsonify({"ok": True})

    @app.route("/api/apps/toggle", methods=["POST"])
    def api_apps_toggle():
        storage = _get_storage()
        data = request.get_json(force=True)
        name = (data.get("name") or "").strip()
        type_ = (data.get("type") or "").strip()
        checked = bool(data.get("checked"))
        if not name or not type_:
            return jsonify({"ok": False, "error": "missing name or type"}), 400
        try:
            if type_ == "trusted":
                if checked:
                    storage.add_allowlist_entry(name, manual=True)
                else:
                    storage.remove_allowlist_entry(name)
            elif type_ == "protected":
                if checked:
                    storage.set_allowlist_blocked(name, True)
                    storage.add_blocklist_entry("app", name, reason="User blocked via dashboard")
                else:
                    storage.set_allowlist_blocked(name, False)
                    storage.remove_blocklist_entry("app", name)
            else:
                return jsonify({"ok": False, "error": "unknown type"}), 400
            return jsonify({"ok": True})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    return app
