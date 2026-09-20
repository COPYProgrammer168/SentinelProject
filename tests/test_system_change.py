"""Test suite for Phase 2 System Change Detector."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.monitor.system_change import SystemChangeDetector
from sentinel.platform_utils.notifier import Notifier


class TestSystemChangeDetector(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)
        self.config = SentinelConfig(db_path=self.tmp_path, snapshot_interval_seconds=0.0)
        self.storage = Storage(self.tmp_path)
        self.notifier = Notifier(enabled=False)
        self.detector = SystemChangeDetector(self.config, self.storage, self.notifier)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    @patch("sentinel.platform_utils.os_system.collect_scheduled_tasks", return_value=[])
    @patch("sentinel.platform_utils.os_system.collect_services", return_value=[])
    @patch("sentinel.platform_utils.os_system.collect_startup_items")
    def test_baseline_and_diff(self, mock_startup, mock_services, mock_tasks):
        # 1. First run: baseline
        mock_startup.return_value = [
            {"item_key": "Startup:App1", "item_path": "C:\\App1.exe", "item_state": "enabled", "hash": "h1"},
            {"item_key": "Startup:App2", "item_path": "C:\\App2.exe", "item_state": "enabled", "hash": "h2"},
        ]
        res1 = self.detector.check_changes(force=True)
        self.assertEqual(res1["new_items"], 0)
        self.assertEqual(len(self.storage.get_recent_alerts()), 0)

        # 2. Second run: identical items (no changes)
        res2 = self.detector.check_changes(force=True)
        self.assertEqual(res2["new_items"], 0)
        self.assertEqual(res2["modified_items"], 0)

        # 3. Third run: inject unexpected persistence item
        mock_startup.return_value = [
            {"item_key": "Startup:App1", "item_path": "C:\\App1.exe", "item_state": "enabled", "hash": "h1"},
            {"item_key": "Startup:App2", "item_path": "C:\\App2.exe", "item_state": "enabled", "hash": "h2"},
            {"item_key": "Startup:Backdoor", "item_path": "C:\\bad.exe", "item_state": "enabled", "hash": "bad_h"},
        ]
        res3 = self.detector.check_changes(force=True)
        self.assertEqual(res3["new_items"], 1)

        alerts = self.storage.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "system_new_startup")
        self.assertEqual(alerts[0]["target_item"], "Startup:Backdoor")

        # 4. Fourth run: modify an existing item
        mock_startup.return_value = [
            {"item_key": "Startup:App1", "item_path": "C:\\App1_hijacked.exe", "item_state": "enabled", "hash": "h1_mod"},
            {"item_key": "Startup:App2", "item_path": "C:\\App2.exe", "item_state": "enabled", "hash": "h2"},
            {"item_key": "Startup:Backdoor", "item_path": "C:\\bad.exe", "item_state": "enabled", "hash": "bad_h"},
        ]
        res4 = self.detector.check_changes(force=True)
        self.assertEqual(res4["new_items"], 0)
        self.assertEqual(res4["modified_items"], 1)

        alerts = self.storage.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["alert_type"], "system_modified_startup")


if __name__ == "__main__":
    unittest.main()
