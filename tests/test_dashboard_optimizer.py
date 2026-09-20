"""Tests for counter reset, apps discovery, optimizer, and dashboard."""

import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.platform_utils.apps import get_all_apps, get_running_apps
from sentinel.platform_utils.optimizer import get_candidates, is_protected, optimize_now


class TestCounterReset(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)
        self.config = SentinelConfig(db_path=self.tmp_path)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    def test_period_stats_tracks_since_start(self):
        storage = Storage(self.tmp_path)
        period_start = storage.get_period_start()
        stats = storage.get_period_stats()
        self.assertIn("period_start", stats)
        self.assertIn("alerts_total", stats)

    def test_reset_counters_creates_summary(self):
        storage = Storage(self.tmp_path)
        before = storage.get_period_stats()
        summary = storage.reset_counters()
        self.assertIn("period_end", summary)
        self.assertIn("network_events_total", summary)
        history = storage.get_period_history()
        self.assertEqual(len(history), 1)

    def test_retention_policy_does_nothing_when_disabled(self):
        storage = Storage(self.tmp_path)
        result = storage.apply_retention()
        self.assertEqual(result["deleted_events"], 0)

    def test_retention_policy_deletes_old_records(self):
        storage = Storage(self.tmp_path)
        storage.set_retention_days(1)
        old_ts = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        with storage._connection() as conn:
            conn.execute("INSERT INTO network_events (timestamp, process_name, local_ip, local_port, remote_ip, remote_port, protocol, status) VALUES (?, '', '', 0, '', 0, '', '')", (old_ts,))
            conn.execute("INSERT INTO alerts (timestamp, alert_type, severity, target_item, message) VALUES (?, '', 'log_only', '', '')", (old_ts,))
        result = storage.apply_retention()
        self.assertGreater(result["deleted_events"], 0)


class TestAppsDiscovery(unittest.TestCase):
    def test_running_apps_returns_list(self):
        apps = get_running_apps()
        self.assertIsInstance(apps, list)

    def test_all_apps_has_trusted_and_protected_flags(self):
        apps = get_all_apps()
        if apps:
            for app in apps:
                self.assertIn("trusted", app)
                self.assertIn("protected", app)


class TestOptimizer(unittest.TestCase):
    def test_is_protected_blocks_sentinel(self):
        self.assertTrue(is_protected("sentinel.exe", 1234))

    def test_is_protected_blocks_system_processes(self):
        self.assertTrue(is_protected("csrss.exe", 100))

    def test_get_candidates_returns_list(self):
        candidates = get_candidates()
        self.assertIsInstance(candidates, list)


if __name__ == "__main__":
    unittest.main()
