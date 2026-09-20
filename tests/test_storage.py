"""Test suite for SQLite storage."""

import os
import tempfile
import unittest
from sentinel.db.storage import Storage


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)
        self.storage = Storage(self.tmp_path)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    def test_meta_and_learning_mode(self):
        self.assertIsNone(self.storage.get_meta("nonexistent"))
        self.storage.set_meta("test_key", "test_val")
        self.assertEqual(self.storage.get_meta("test_key"), "test_val")

        # Learning mode
        until = self.storage.init_learning_mode_if_needed(duration_days=7.0)
        self.assertIsNotNone(until)
        self.assertTrue(self.storage.is_learning_mode_active())

        # Disable learning mode
        self.storage.disable_learning_mode()
        self.assertFalse(self.storage.is_learning_mode_active())

    def test_allowlist_operations(self):
        self.assertFalse(self.storage.is_process_allowed("chrome.exe"))

        # Add during learning mode
        self.storage.record_process_observed("chrome.exe", is_learning_mode=True)
        self.assertTrue(self.storage.is_process_allowed("chrome.exe"))

        # Increment count
        self.storage.record_process_observed("chrome.exe", is_learning_mode=False)
        allowlist = self.storage.get_allowlist()
        self.assertEqual(len(allowlist), 1)
        self.assertEqual(allowlist[0]["process_name"], "chrome.exe")
        self.assertEqual(allowlist[0]["connection_count"], 2)

        # Manual addition
        self.storage.add_allowlist_entry("slack.exe", manual=True)
        self.assertTrue(self.storage.is_process_allowed("slack.exe"))

        # Remove entry
        self.assertTrue(self.storage.remove_allowlist_entry("chrome.exe"))
        self.assertFalse(self.storage.is_process_allowed("chrome.exe"))

    def test_network_events_logging(self):
        events = [
            {
                "timestamp": "2026-09-20T10:00:00Z",
                "pid": 1234,
                "process_name": "curl.exe",
                "local_ip": "192.168.1.10",
                "local_port": 50000,
                "remote_ip": "93.184.216.34",
                "remote_port": 80,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "bytes_sent": 100,
                "bytes_recv": 200,
                "is_flagged": 1,
                "flag_reason": "Not in allowlist",
            }
        ]
        self.storage.log_network_events(events)
        recent = self.storage.get_recent_network_events(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["process_name"], "curl.exe")
        self.assertEqual(recent[0]["is_flagged"], 1)

    def test_system_snapshots_and_diff(self):
        items_v1 = [
            {"item_key": "Startup:OneDrive", "item_path": "C:\\OneDrive.exe", "item_state": "enabled", "hash": "abc1"},
            {"item_key": "Startup:Teams", "item_path": "C:\\Teams.exe", "item_state": "enabled", "hash": "abc2"},
        ]
        self.storage.record_system_snapshot("startup", items_v1)
        snap = self.storage.get_latest_system_snapshot("startup")
        self.assertEqual(len(snap), 2)
        self.assertIn("Startup:OneDrive", snap)

    def test_alert_recording(self):
        alert_id = self.storage.record_alert(
            alert_type="network_unauthorized",
            severity="high",
            target_item="netcat.exe",
            remote_ip="198.51.100.1",
            message="Unauthorized connection detected",
            notified=True,
        )
        self.assertGreater(alert_id, 0)
        alerts = self.storage.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["target_item"], "netcat.exe")


if __name__ == "__main__":
    unittest.main()
