"""Tests for alert deduplication, cooldown, and snooze."""

import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage


class TestAlertDedup(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)
        self.config = SentinelConfig(db_path=self.tmp_path, notification_cooldown_minutes=30)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    def test_first_occurrence_notifies(self):
        """First time an alert identity is seen, it should not be in cooldown."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("proc.exe", "network_unauthorized", "1.2.3.4", "high", 30)
        self.assertEqual(identity["occurrence_count"], 1)
        self.assertFalse(storage.is_alert_in_cooldown(identity["identity_key"], 30))

    def test_second_occurrence_within_cooldown(self):
        """Second occurrence within cooldown should be suppressed."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("proc.exe", "network_unauthorized", "1.2.3.4", "medium", 30)
        storage.record_alert_notification(identity["identity_key"])
        self.assertTrue(storage.is_alert_in_cooldown(identity["identity_key"], 30))

        identity2 = storage.record_alert_identity("proc.exe", "network_unauthorized", "1.2.3.4", "medium", 30)
        self.assertEqual(identity2["occurrence_count"], 2)
        self.assertTrue(storage.is_alert_in_cooldown(identity2["identity_key"], 30))

    def test_third_occurrence_after_cooldown(self):
        """After cooldown expires, the alert should notify again."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("proc.exe", "network_trusted_unrecognized", "1.2.3.4", "low", 30)
        storage.record_alert_notification(identity["identity_key"])

        past_time = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()
        with storage._connection() as conn:
            conn.execute(
                "UPDATE alert_identities SET last_notified_at = ? WHERE identity_key = ?",
                (past_time, identity["identity_key"]),
            )

        self.assertFalse(storage.is_alert_in_cooldown(identity["identity_key"], 30))

    def test_high_severity_bypasses_cooldown(self):
        """High severity alerts should never be in cooldown."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("unknown.exe", "network_unauthorized", "1.2.3.4", "high", 30)
        storage.record_alert_notification(identity["identity_key"])

        identity2 = storage.record_alert_identity("unknown.exe", "network_unauthorized", "1.2.3.4", "high", 30)
        self.assertFalse(storage.is_alert_in_cooldown(identity2["identity_key"], 30))

    def test_snooze_alert(self):
        """Snoozing an alert should suppress notifications until snooze expires."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("proc.exe", "network_trusted_unrecognized", "1.2.3.4", "low", 30)
        storage.record_alert_notification(identity["identity_key"])

        storage.snooze_alert(identity["identity_key"], duration="1hr")
        self.assertTrue(storage.is_alert_in_cooldown(identity["identity_key"], 30))

    def test_unsnooze_alert(self):
        """Unsnoozing an alert should remove the snooze."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("proc.exe", "network_trusted_unrecognized", "1.2.3.4", "low", 30)
        storage.snooze_alert(identity["identity_key"], duration="1hr")
        self.assertTrue(storage.is_alert_in_cooldown(identity["identity_key"], 30))

        storage.unsnooze_alert(identity["identity_key"])
        self.assertFalse(storage.is_alert_in_cooldown(identity["identity_key"], 30))

    def test_get_grouped_alerts(self):
        """Grouped alerts should return alert identities."""
        storage = Storage(self.tmp_path)
        storage.record_alert_identity("proc.exe", "network_trusted_unrecognized", "1.2.3.4", "low", 30)
        storage.record_alert_identity("other.exe", "network_unauthorized", "2.3.4.5", "high", 30)

        grouped = storage.get_grouped_alerts()
        self.assertEqual(len(grouped), 2)
        procs = {g["process_name"] for g in grouped}
        self.assertIn("proc.exe", procs)
        self.assertIn("other.exe", procs)

    def test_get_snoozed_alerts(self):
        """Snoozed alerts should be returned by get_snoozed_alerts."""
        storage = Storage(self.tmp_path)
        identity = storage.record_alert_identity("proc.exe", "network_trusted_unrecognized", "1.2.3.4", "low", 30)
        storage.snooze_alert(identity["identity_key"], duration="forever")

        snoozed = storage.get_snoozed_alerts()
        self.assertEqual(len(snoozed), 1)
        self.assertEqual(snoozed[0]["identity_key"], identity["identity_key"])


if __name__ == "__main__":
    unittest.main()
