"""Test migration from old allowlist schema."""
import os
import tempfile
import sqlite3
import unittest
from sentinel.db.storage import Storage


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    def test_migrate_old_allowlist_schema(self):
        """Simulate old schema and verify migration works."""
        # Create old-schema database manually
        conn = sqlite3.connect(self.tmp_path)
        conn.execute("""
            CREATE TABLE allowlist (
                process_name TEXT PRIMARY KEY COLLATE NOCASE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                connection_count INTEGER DEFAULT 1,
                is_manual INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0
            );
        """)
        conn.execute(
            "INSERT INTO allowlist (process_name, first_seen, last_seen, connection_count, is_manual, is_blocked) VALUES (?, ?, ?, 5, 1, 0)",
            ("old_process.exe", "2026-01-01", "2026-01-02"),
        )
        conn.execute(
            "INSERT INTO allowlist (process_name, first_seen, last_seen, connection_count, is_manual, is_blocked) VALUES (?, ?, ?, 3, 0, 0)",
            ("another_old.exe", "2026-01-03", "2026-01-04"),
        )
        conn.commit()
        conn.close()

        # Now open with Storage - should trigger migration
        storage = Storage(self.tmp_path)

        # Verify migration happened
        entries = storage.get_allowlist()
        self.assertEqual(len(entries), 2)

        # Verify old entries are preserved
        names = {e["process_name"] for e in entries}
        self.assertIn("old_process.exe", names)
        self.assertIn("another_old.exe", names)

        # Verify old entry data is preserved
        old_entry = next(e for e in entries if e["process_name"] == "old_process.exe")
        self.assertEqual(old_entry["connection_count"], 5)
        self.assertEqual(old_entry["is_manual"], 1)
        self.assertEqual(old_entry["is_blocked"], 0)
        self.assertEqual(old_entry["first_seen"], "2026-01-01")
        self.assertEqual(old_entry["last_seen"], "2026-01-02")

        # Verify new fields exist
        self.assertIn("executable_path", old_entry)
        self.assertIn("signer", old_entry)
        self.assertIn("file_hash", old_entry)

        # Verify schema version
        self.assertEqual(storage.get_meta("allowlist_schema_version"), "2")

    def test_migration_preserves_manual_entries(self):
        """Verify manually-approved entries are preserved during migration."""
        conn = sqlite3.connect(self.tmp_path)
        conn.execute("""
            CREATE TABLE allowlist (
                process_name TEXT PRIMARY KEY COLLATE NOCASE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                connection_count INTEGER DEFAULT 1,
                is_manual INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0
            );
        """)
        conn.execute(
            "INSERT INTO allowlist VALUES ('manual_app.exe', '2026-01-01', '2026-01-02', 10, 1, 0)",
        )
        conn.execute(
            "INSERT INTO allowlist VALUES ('blocked_app.exe', '2026-01-01', '2026-01-02', 2, 0, 1)",
        )
        conn.commit()
        conn.close()

        storage = Storage(self.tmp_path)
        entries = storage.get_allowlist()

        manual_entry = next(e for e in entries if e["process_name"] == "manual_app.exe")
        self.assertEqual(manual_entry["is_manual"], 1)
        self.assertEqual(manual_entry["connection_count"], 10)

        blocked_entry = next(e for e in entries if e["process_name"] == "blocked_app.exe")
        self.assertEqual(blocked_entry["is_blocked"], 1)


if __name__ == "__main__":
    unittest.main()
