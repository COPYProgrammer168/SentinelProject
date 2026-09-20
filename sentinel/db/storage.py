"""SQLite storage manager for Sentinel."""

from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional


class Storage:
    def __init__(self, db_path: str = "sentinel.db"):
        self.db_path = str(Path(db_path).resolve())
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create necessary tables and indices if not already present."""
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS allowlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT NOT NULL COLLATE NOCASE,
                    executable_path TEXT NOT NULL DEFAULT '',
                    signer TEXT NOT NULL DEFAULT '',
                    file_hash TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 1,
                    is_manual INTEGER DEFAULT 0,
                    is_blocked INTEGER DEFAULT 0,
                    UNIQUE(process_name)
                );

                CREATE TABLE IF NOT EXISTS trusted_signers (
                    signer TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    is_manual INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS user_severity_overrides (
                    alert_type TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    reason TEXT
                );

                CREATE TABLE IF NOT EXISTS period_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period_start TEXT NOT NULL,
                    period_end TEXT NOT NULL,
                    period_type TEXT NOT NULL,
                    network_events_total INTEGER DEFAULT 0,
                    network_events_flagged INTEGER DEFAULT 0,
                    alerts_total INTEGER DEFAULT 0,
                    alerts_critical INTEGER DEFAULT 0,
                    alerts_log_only INTEGER DEFAULT 0,
                    new_allowlist_entries INTEGER DEFAULT 0,
                    new_blocklist_entries INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS blocklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    reason TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    UNIQUE(target_type, target_value)
                );

                CREATE TABLE IF NOT EXISTS flagged_software (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    process_name TEXT NOT NULL,
                    executable_path TEXT NOT NULL,
                    signer TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS provider_cidrs (
                    provider TEXT PRIMARY KEY,
                    cidr_list TEXT NOT NULL,
                    last_refreshed TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alert_identities (
                    identity_key TEXT PRIMARY KEY,
                    process_name TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    remote_ip TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    last_notified_at TEXT,
                    snoozed_until TEXT DEFAULT '',
                    severity TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    status TEXT,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_recv INTEGER DEFAULT 0,
                    is_flagged INTEGER DEFAULT 0,
                    flag_reason TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_net_events_ts ON network_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_net_events_proc ON network_events(process_name);
                CREATE INDEX IF NOT EXISTS idx_net_events_flagged ON network_events(is_flagged);

                CREATE TABLE IF NOT EXISTS system_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    item_path TEXT,
                    item_state TEXT,
                    hash TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_snapshots_cat_key ON system_snapshots(category, item_key);
                CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON system_snapshots(timestamp);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target_item TEXT NOT NULL,
                    remote_ip TEXT,
                    message TEXT NOT NULL,
                    notified INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
                """
            )

        self._migrate_allowlist()
        self._migrate_blocklist_unique()

    def _migrate_allowlist(self) -> None:
        """One-time migration from old allowlist schema to new identity-based schema."""
        with self._connection() as conn:
            migrated = conn.execute(
                "SELECT value FROM meta WHERE key = 'allowlist_schema_version'"
            ).fetchone()

            if migrated and migrated["value"] == "2":
                return

            columns = conn.execute("PRAGMA table_info(allowlist)").fetchall()
            column_names = [c["name"] for c in columns]

            if "executable_path" in column_names:
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('allowlist_schema_version', '2')"
                )
                return

            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS allowlist_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT NOT NULL COLLATE NOCASE,
                    executable_path TEXT NOT NULL DEFAULT '',
                    signer TEXT NOT NULL DEFAULT '',
                    file_hash TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 1,
                    is_manual INTEGER DEFAULT 0,
                    is_blocked INTEGER DEFAULT 0
                );
                """
            )

            conn.execute(
                """
                INSERT INTO allowlist_new (process_name, executable_path, signer, file_hash, first_seen, last_seen, connection_count, is_manual, is_blocked)
                SELECT process_name, '', '', '', first_seen, last_seen, connection_count, is_manual, is_blocked
                FROM allowlist
                """
            )

            conn.execute("DROP TABLE allowlist")
            conn.execute("ALTER TABLE allowlist_new RENAME TO allowlist")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_allowlist_name ON allowlist(process_name)")

            # Backfill identity info for migrated entries
            rows = conn.execute("SELECT process_name FROM allowlist").fetchall()
            for row in rows:
                pname = row["process_name"]
                exe_path, signer, file_hash = self._try_backfill_identity(pname)
                if exe_path:
                    conn.execute(
                        "UPDATE allowlist SET executable_path=?, signer=?, file_hash=? WHERE process_name=?",
                        (exe_path, signer, file_hash, pname),
                    )

            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('allowlist_schema_version', '2')"
            )

    def _try_backfill_identity(self, process_name: str) -> Tuple[str, str, str]:
        """Try to find executable path, signer, and hash for a known process name."""
        import psutil

        exe_path = ""
        signer = ""
        file_hash = ""

        try:
            for proc in psutil.process_iter(["name", "exe"]):
                try:
                    if proc.info["name"] and proc.info["name"].lower() == process_name.lower():
                        if proc.info["exe"]:
                            exe_path = proc.info["exe"]
                            from sentinel.platform_utils.signer import get_signer_info, get_file_hash
                            signer, _ = get_signer_info(exe_path)
                            file_hash = get_file_hash(exe_path)
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

        return exe_path, signer, file_hash

    def _migrate_blocklist_unique(self) -> None:
        with self._connection() as conn:
            cols = conn.execute("PRAGMA table_info(blocklist)").fetchall()
            has_unique = any(c["name"] == "target_type" for c in cols) and "UNIQUE(target_type, target_value)" in (
                conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocklist'").fetchone()["sql"] or ""
            )
            if has_unique:
                return
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS blocklist_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    reason TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    UNIQUE(target_type, target_value)
                );
                INSERT OR IGNORE INTO blocklist_new SELECT * FROM blocklist;
                DROP TABLE blocklist;
                ALTER TABLE blocklist_new RENAME TO blocklist;
                CREATE INDEX IF NOT EXISTS idx_blocklist_target ON blocklist(target_type, target_value);
                """
            )

    # ---------------- Meta / Configuration ----------------

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._connection() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def init_learning_mode_if_needed(self, duration_days: float) -> str:
        until_str = self.get_meta("learning_mode_until")
        if not until_str:
            end_dt = datetime.now(timezone.utc) + timedelta(days=duration_days)
            until_str = end_dt.isoformat()
            self.set_meta("learning_mode_until", until_str)
            self.set_meta("initialized_at", datetime.now(timezone.utc).isoformat())
        return until_str

    def is_learning_mode_active(self) -> bool:
        until_str = self.get_meta("learning_mode_until")
        if not until_str:
            return False
        try:
            until_dt = datetime.fromisoformat(until_str)
            return datetime.now(timezone.utc) < until_dt
        except Exception:
            return False

    def disable_learning_mode(self) -> None:
        past_iso = datetime.now(timezone.utc).isoformat()
        self.set_meta("learning_mode_until", past_iso)

    # ---------------- Allowlist Baseline ----------------

    def record_process_observed(
        self,
        process_name: str,
        is_learning_mode: bool,
        executable_path: str = "",
        signer: str = "",
        file_hash: str = "",
    ) -> None:
        """Update allowlist. If learning mode, automatically adds or increments."""
        if not process_name:
            return
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT process_name, connection_count FROM allowlist WHERE process_name = ?",
                (process_name,),
            ).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE allowlist SET last_seen = ?, connection_count = connection_count + 1
                    WHERE process_name = ?
                    """,
                    (now_iso, process_name),
                )
            elif is_learning_mode:
                conn.execute(
                    """
                    INSERT INTO allowlist
                        (process_name, executable_path, signer, file_hash, first_seen, last_seen, connection_count, is_manual, is_blocked)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0)
                    """,
                    (process_name, executable_path, signer, file_hash, now_iso, now_iso),
                )

    def is_process_allowed(
        self,
        process_name: str,
        executable_path: str = "",
        signer: str = "",
    ) -> bool:
        """Check if a process is on the allowlist.

        Matching logic:
        - If DB entry has non-empty executable_path: incoming path must match
        - If DB entry has non-empty signer: incoming signer must match
        - If both are empty (legacy entry): name-only match (backward compat)
        - Also returns True if the process's signer is in the global trusted signers list
        """
        if not process_name:
            return False
        with self._connection() as conn:
            row = conn.execute(
                "SELECT is_blocked, executable_path, signer FROM allowlist WHERE process_name = ?",
                (process_name,),
            ).fetchone()
            if row and row["is_blocked"] == 0:
                stored_path = row["executable_path"] or ""
                stored_signer = row["signer"] or ""

                if stored_path or stored_signer:
                    path_match = True
                    signer_match = True
                    if stored_path and executable_path and stored_path != executable_path:
                        path_match = False
                    if stored_signer and signer and stored_signer != signer:
                        signer_match = False
                    if path_match and signer_match:
                        return True
                    if stored_signer and self._is_trusted_signer(stored_signer):
                        return True
                    return path_match and signer_match
                return True
            return False

    def _is_trusted_signer(self, signer: str) -> bool:
        """Check if a signer is in the global trusted signers list."""
        if not signer:
            return False
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM trusted_signers WHERE signer = ?", (signer,)
            ).fetchone()
            return row is not None

    def add_allowlist_entry(
        self,
        process_name: str,
        manual: bool = True,
        executable_path: str = "",
        signer: str = "",
        file_hash: str = "",
    ) -> None:
        if not process_name:
            return
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT process_name FROM allowlist WHERE process_name = ?",
                (process_name,),
            ).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE allowlist SET
                        last_seen = ?,
                        is_blocked = 0,
                        is_manual = CASE WHEN ? THEN 1 ELSE is_manual END,
                        executable_path = CASE WHEN ? != '' THEN ? ELSE executable_path END,
                        signer = CASE WHEN ? != '' THEN ? ELSE signer END,
                        file_hash = CASE WHEN ? != '' THEN ? ELSE file_hash END
                    WHERE process_name = ?
                    """,
                    (
                        now_iso, manual, executable_path, executable_path,
                        signer, signer, file_hash, file_hash,
                        process_name,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO allowlist
                        (process_name, executable_path, signer, file_hash, first_seen, last_seen, connection_count, is_manual, is_blocked)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0)
                    """,
                    (
                        process_name, executable_path, signer, file_hash,
                        now_iso, now_iso, 1 if manual else 0,
                    ),
                )

    def remove_allowlist_entry(self, process_name: str) -> bool:
        with self._connection() as conn:
            cur = conn.execute("DELETE FROM allowlist WHERE process_name = ?", (process_name,))
            return cur.rowcount > 0

    def get_allowlist(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM allowlist ORDER BY process_name ASC").fetchall()
            return [dict(r) for r in rows]

    def get_allowlist_entry(self, process_name: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM allowlist WHERE process_name = ?", (process_name,)).fetchone()
            return dict(row) if row else None

    def set_allowlist_blocked(self, process_name: str, blocked: bool) -> None:
        with self._connection() as conn:
            conn.execute("UPDATE allowlist SET is_blocked = ? WHERE process_name = ?", (1 if blocked else 0, process_name))

    # ---------------- Trusted Signers ----------------

    def add_trusted_signer(self, signer: str, manual: bool = True) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO trusted_signers (signer, first_seen, is_manual)
                VALUES (?, ?, ?)
                ON CONFLICT(signer) DO UPDATE SET is_manual = excluded.is_manual, first_seen = excluded.first_seen
                """,
                (signer, now_iso, 1 if manual else 0),
            )

    def remove_trusted_signer(self, signer: str) -> bool:
        with self._connection() as conn:
            cur = conn.execute("DELETE FROM trusted_signers WHERE signer = ?", (signer,))
            return cur.rowcount > 0

    def get_trusted_signers(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM trusted_signers ORDER BY signer ASC").fetchall()
            return [dict(r) for r in rows]

    def is_signer_trusted(self, signer: str) -> bool:
        if not signer:
            return False
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM trusted_signers WHERE signer = ?", (signer,)
            ).fetchone()
            return row is not None

    # ---------------- User Severity Overrides ----------------

    def add_severity_override(self, alert_type: str, severity: str, reason: str = "") -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO user_severity_overrides (alert_type, severity, reason)
                VALUES (?, ?, ?)
                ON CONFLICT(alert_type) DO UPDATE SET severity = excluded.severity, reason = excluded.reason
                """,
                (alert_type, severity, reason),
            )

    def remove_severity_override(self, alert_type: str) -> bool:
        with self._connection() as conn:
            cur = conn.execute("DELETE FROM user_severity_overrides WHERE alert_type = ?", (alert_type,))
            return cur.rowcount > 0

    def get_severity_overrides(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM user_severity_overrides").fetchall()
            return [dict(r) for r in rows]

    def get_effective_severity(self, alert_type: str, default_severity: str) -> str:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT severity FROM user_severity_overrides WHERE alert_type = ?",
                (alert_type,),
            ).fetchone()
            if row:
                return row["severity"]
            return default_severity

    # ---------------- Blocklist ----------------

    def add_blocklist_entry(self, target_type: str, target_value: str, reason: str = "") -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT target_type, target_value FROM blocklist WHERE target_type = ? AND target_value = ?",
                (target_type, target_value),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE blocklist SET reason = ?, last_seen = ?, is_active = 1 WHERE target_type = ? AND target_value = ?",
                    (reason, now_iso, target_type, target_value),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO blocklist (target_type, target_value, reason, first_seen, last_seen, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                    """,
                    (target_type, target_value, reason, now_iso, now_iso),
                )

    def remove_blocklist_entry(self, target_type: str, target_value: str) -> bool:
        with self._connection() as conn:
            cur = conn.execute(
                "DELETE FROM blocklist WHERE target_type = ? AND target_value = ?",
                (target_type, target_value),
            )
            return cur.rowcount > 0

    def get_blocklist(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM blocklist WHERE is_active = 1 ORDER BY target_type, target_value").fetchall()
            return [dict(r) for r in rows]

    def is_blocked(self, target_type: str, target_value: str) -> bool:
        if not target_type or not target_value:
            return False
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM blocklist WHERE target_type = ? AND target_value = ? AND is_active = 1",
                (target_type, target_value),
            ).fetchone()
            return row is not None

    # ---------------- Flagged Software ----------------

    def record_flagged_software(self, pid: int, process_name: str, executable_path: str, signer: str, reason: str) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO flagged_software (pid, process_name, executable_path, signer, reason, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(process_name, executable_path) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (pid, process_name, executable_path, signer, reason, now_iso, now_iso),
            )
            return cur.lastrowid

    def get_flagged_software(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM flagged_software ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ---------------- Provider CIDRs ----------------

    def get_provider_cidrs(self) -> Dict[str, List[str]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT provider, cidr_list FROM provider_cidrs").fetchall()
            result = {}
            for row in rows:
                try:
                    import json
                    result[row["provider"]] = json.loads(row["cidr_list"])
                except Exception:
                    result[row["provider"]] = []
            return result

    def update_provider_cidrs(self, provider: str, cidr_list: List[str]) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        import json
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO provider_cidrs (provider, cidr_list, last_refreshed)
                VALUES (?, ?, ?)
                ON CONFLICT(provider) DO UPDATE SET cidr_list = excluded.cidr_list, last_refreshed = excluded.last_refreshed
                """,
                (provider, json.dumps(cidr_list), now_iso),
            )

    # ---------------- Alert Identity / Dedup / Snooze ----------------

    @staticmethod
    def _make_alert_identity_key(process_name: str, alert_type: str, remote_ip: Optional[str]) -> str:
        return f"{process_name}|{alert_type}|{remote_ip or ''}"

    def record_alert_identity(
        self,
        process_name: str,
        alert_type: str,
        remote_ip: Optional[str],
        severity: str,
        cooldown_minutes: int,
    ) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        identity_key = self._make_alert_identity_key(process_name, alert_type, remote_ip)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT occurrence_count, last_notified_at, snoozed_until FROM alert_identities WHERE identity_key = ?",
                (identity_key,),
            ).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE alert_identities
                    SET last_seen = ?, occurrence_count = occurrence_count + 1
                    WHERE identity_key = ?
                    """,
                    (now_iso, identity_key),
                )
                return {
                    "identity_key": identity_key,
                    "occurrence_count": row["occurrence_count"] + 1,
                    "last_notified_at": row["last_notified_at"],
                    "snoozed_until": row["snoozed_until"] or "",
                }
            conn.execute(
                """
                INSERT INTO alert_identities
                    (identity_key, process_name, alert_type, remote_ip, first_seen, last_seen, occurrence_count, last_notified_at, snoozed_until, severity)
                VALUES (?, ?, ?, ?, ?, ?, 1, NULL, '', ?)
                """,
                (identity_key, process_name, alert_type, remote_ip, now_iso, now_iso, severity),
            )
            return {
                "identity_key": identity_key,
                "occurrence_count": 1,
                "last_notified_at": None,
                "snoozed_until": "",
            }

    def is_alert_in_cooldown(self, identity_key: str, cooldown_minutes: int) -> bool:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT last_notified_at, snoozed_until, severity FROM alert_identities WHERE identity_key = ?",
                (identity_key,),
            ).fetchone()
            if not row:
                return False
            if (row["severity"] or "").lower() == "high":
                return False
            snoozed_until = row["snoozed_until"] or ""
            if snoozed_until:
                try:
                    if datetime.now(timezone.utc) < datetime.fromisoformat(snoozed_until):
                        return True
                except Exception:
                    pass
            last_notified = row["last_notified_at"]
            if not last_notified:
                return False
            try:
                last_dt = datetime.fromisoformat(last_notified)
                if (datetime.now(timezone.utc) - last_dt) < timedelta(minutes=cooldown_minutes):
                    return True
            except Exception:
                pass
            return False

    def record_alert_notification(self, identity_key: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                "UPDATE alert_identities SET last_notified_at = ? WHERE identity_key = ?",
                (now_iso, identity_key),
            )

    def snooze_alert(self, identity_key: str, duration: str = "forever") -> None:
        now = datetime.now(timezone.utc)
        if duration == "1hr":
            snoozed_until = (now + timedelta(hours=1)).isoformat()
        elif duration == "24hr":
            snoozed_until = (now + timedelta(hours=24)).isoformat()
        else:
            snoozed_until = "2099-12-31T00:00:00+00:00"
        with self._connection() as conn:
            conn.execute(
                "UPDATE alert_identities SET snoozed_until = ? WHERE identity_key = ?",
                (snoozed_until, identity_key),
            )

    def unsnooze_alert(self, identity_key: str) -> None:
        with self._connection() as conn:
            conn.execute(
                "UPDATE alert_identities SET snoozed_until = '' WHERE identity_key = ?",
                (identity_key,),
            )

    def get_grouped_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT identity_key, process_name, alert_type, remote_ip, first_seen, last_seen,
                       occurrence_count, last_notified_at, snoozed_until, severity
                FROM alert_identities
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_snoozed_alerts(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT identity_key, process_name, alert_type, remote_ip, first_seen, last_seen,
                       occurrence_count, last_notified_at, snoozed_until, severity
                FROM alert_identities
                WHERE snoozed_until != '' AND snoozed_until IS NOT NULL
                ORDER BY last_seen DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def get_alert_individual_instances(self, identity_key: str) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT a.id, a.timestamp, a.alert_type, a.severity, a.target_item, a.remote_ip, a.message, a.notified
                FROM alerts a
                JOIN alert_identities ai ON ai.process_name = a.target_item AND ai.alert_type = a.alert_type
                WHERE ai.identity_key = ?
                ORDER BY a.id DESC
                LIMIT 100
                """,
                (identity_key,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_alert_individual_instances(self, identity_key: str) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT a.id, a.timestamp, a.alert_type, a.severity, a.target_item, a.remote_ip, a.message, a.notified
                FROM alerts a
                JOIN alert_identities ai ON ai.process_name = a.target_item AND ai.alert_type = a.alert_type
                WHERE ai.identity_key = ?
                ORDER BY a.id DESC
                LIMIT 100
                """,
                (identity_key,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ---------------- Network Events ----------------

    def log_network_events(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        with self._connection() as conn:
            conn.executemany(
                """
                INSERT INTO network_events (
                    timestamp, pid, process_name, local_ip, local_port,
                    remote_ip, remote_port, protocol, status, bytes_sent,
                    bytes_recv, is_flagged, flag_reason
                ) VALUES (
                    :timestamp, :pid, :process_name, :local_ip, :local_port,
                    :remote_ip, :remote_port, :protocol, :status, :bytes_sent,
                    :bytes_recv, :is_flagged, :flag_reason
                )
                """,
                events,
            )

    def get_recent_network_events(self, limit: int = 50, flagged_only: bool = False) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            query = "SELECT * FROM network_events"
            params: List[Any] = []
            if flagged_only:
                query += " WHERE is_flagged = 1"
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ---------------- System Snapshots ----------------

    def get_latest_system_snapshot(self, category: str) -> Dict[str, Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT timestamp FROM system_snapshots WHERE category = ? ORDER BY id DESC LIMIT 1",
                (category,),
            ).fetchone()
            if not row:
                return {}
            latest_ts = row["timestamp"]
            rows = conn.execute(
                "SELECT item_key, item_path, item_state, hash FROM system_snapshots WHERE category = ? AND timestamp = ?",
                (category, latest_ts),
            ).fetchall()
            return {r["item_key"]: dict(r) for r in rows}

    def record_system_snapshot(self, category: str, items: List[Dict[str, Any]], timestamp: Optional[str] = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            data = [
                (ts, category, item["item_key"], item.get("item_path", ""), item.get("item_state", ""), item.get("hash", ""))
                for item in items
            ]
            conn.executemany(
                """
                INSERT INTO system_snapshots (timestamp, category, item_key, item_path, item_state, hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                data,
            )

    # ---------------- Alerts ----------------

    def record_alert(
        self,
        alert_type: str,
        severity: str,
        target_item: str,
        message: str,
        remote_ip: Optional[str] = None,
        notified: bool = True,
    ) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (timestamp, alert_type, severity, target_item, remote_ip, message, notified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now_iso, alert_type, severity, target_item, remote_ip, message, 1 if notified else 0),
            )
            return cur.lastrowid

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ---------------- Stats & Health ----------------

    def get_stats(self) -> Dict[str, Any]:
        with self._connection() as conn:
            period_start = self.get_period_start()
            allowlist_count = conn.execute("SELECT COUNT(*) as c FROM allowlist").fetchone()["c"]
            event_count = conn.execute("SELECT COUNT(*) as c FROM network_events WHERE timestamp >= ?", (period_start,)).fetchone()["c"]
            flagged_event_count = conn.execute("SELECT COUNT(*) as c FROM network_events WHERE is_flagged = 1 AND timestamp >= ?", (period_start,)).fetchone()["c"]
            alert_count = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE timestamp >= ?", (period_start,)).fetchone()["c"]
            snapshot_count = conn.execute("SELECT COUNT(*) as c FROM system_snapshots WHERE timestamp >= ?", (period_start,)).fetchone()["c"]
            learning_until = self.get_meta("learning_mode_until", "Not configured")
            return {
                "db_path": self.db_path,
                "allowlist_entries": allowlist_count,
                "network_events_total": event_count,
                "network_events_flagged": flagged_event_count,
                "alerts_total": alert_count,
                "system_snapshots_recorded": snapshot_count,
                "learning_mode_until": learning_until,
                "is_learning_mode_active": self.is_learning_mode_active(),
                "period_start": period_start,
                "period_type": self.get_period_type(),
            }

    # ---------------- Period Reset ----------------

    def get_period_start(self) -> str:
        return self.get_meta("period_start", datetime.now(timezone.utc).isoformat())

    def set_period_start(self, period_start: str) -> None:
        self.set_meta("period_start", period_start)

    def get_period_type(self) -> str:
        return self.get_meta("period_type", "daily")

    def set_period_type(self, period_type: str) -> None:
        self.set_meta("period_type", period_type)

    def get_period_stats(self) -> Dict[str, Any]:
        period_start = self.get_period_start()
        with self._connection() as conn:
            event_count = conn.execute("SELECT COUNT(*) as c FROM network_events WHERE timestamp >= ?", (period_start,)).fetchone()["c"]
            flagged_event_count = conn.execute("SELECT COUNT(*) as c FROM network_events WHERE is_flagged = 1 AND timestamp >= ?", (period_start,)).fetchone()["c"]
            alert_count = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE timestamp >= ?", (period_start,)).fetchone()["c"]
            critical_count = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity = 'critical' AND timestamp >= ?", (period_start,)).fetchone()["c"]
            log_only_count = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity = 'log_only' AND timestamp >= ?", (period_start,)).fetchone()["c"]
            new_allowlist = conn.execute("SELECT COUNT(*) as c FROM allowlist WHERE first_seen >= ?", (period_start,)).fetchone()["c"]
            new_blocklist = conn.execute("SELECT COUNT(*) as c FROM blocklist WHERE first_seen >= ?", (period_start,)).fetchone()["c"]
            return {
                "period_start": period_start,
                "period_type": self.get_period_type(),
                "network_events_total": event_count,
                "network_events_flagged": flagged_event_count,
                "alerts_total": alert_count,
                "alerts_critical": critical_count,
                "alerts_log_only": log_only_count,
                "new_allowlist_entries": new_allowlist,
                "new_blocklist_entries": new_blocklist,
            }

    def reset_counters(self) -> Dict[str, Any]:
        period_start = self.get_period_start()
        period_type = self.get_period_type()
        now_iso = datetime.now(timezone.utc).isoformat()
        stats = self.get_period_stats()
        stats["period_end"] = now_iso
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO period_summaries
                    (period_start, period_end, period_type, network_events_total, network_events_flagged,
                     alerts_total, alerts_critical, alerts_log_only, new_allowlist_entries, new_blocklist_entries)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stats["period_start"],
                    now_iso,
                    period_type,
                    stats["network_events_total"],
                    stats["network_events_flagged"],
                    stats["alerts_total"],
                    stats["alerts_critical"],
                    stats["alerts_log_only"],
                    stats["new_allowlist_entries"],
                    stats["new_blocklist_entries"],
                ),
            )
        self.set_period_start(now_iso)
        return stats

    def get_period_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM period_summaries ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_retention_days(self) -> Optional[int]:
        val = self.get_meta("retention_days")
        if val is None:
            return None
        try:
            return int(val)
        except ValueError:
            return None

    def set_retention_days(self, days: Optional[int]) -> None:
        self.set_meta("retention_days", str(days) if days is not None else "")

    def apply_retention(self) -> Dict[str, int]:
        retention_days = self.get_retention_days()
        if not retention_days or retention_days <= 0:
            return {"deleted_events": 0, "deleted_alerts": 0, "deleted_snapshots": 0}
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._connection() as conn:
            events_deleted = conn.execute("DELETE FROM network_events WHERE timestamp < ?", (cutoff,)).rowcount
            alerts_deleted = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,)).rowcount
            snapshots_deleted = conn.execute("DELETE FROM system_snapshots WHERE timestamp < ?", (cutoff,)).rowcount
            return {
                "deleted_events": events_deleted,
                "deleted_alerts": alerts_deleted,
                "deleted_snapshots": snapshots_deleted,
            }

