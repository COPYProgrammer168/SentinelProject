"""Test suite for Phase 1 Network Monitor."""

import collections
import os
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.monitor.network import NetworkMonitor
from sentinel.platform_utils.notifier import Notifier

MockAddr = collections.namedtuple("MockAddr", ["ip", "port"])
MockConn = collections.namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


class TestNetworkMonitor(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)
        self.config = SentinelConfig(db_path=self.tmp_path, idle_threshold_seconds=100.0)
        self.storage = Storage(self.tmp_path)
        self.notifier = Notifier(enabled=False)
        self.monitor = NetworkMonitor(self.config, self.storage, self.notifier)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    @patch("sentinel.monitor.network.get_idle_seconds", return_value=10.0)
    @patch("psutil.net_connections")
    def test_learning_mode_populates_allowlist_no_alerts(self, mock_net, mock_idle):
        # Initialize learning mode
        self.storage.init_learning_mode_if_needed(duration_days=7.0)
        self.assertTrue(self.storage.is_learning_mode_active())

        # Setup mock connection for process
        mock_net.return_value = [
            MockConn(
                fd=-1,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                laddr=MockAddr("192.168.1.50", 49152),
                raddr=MockAddr("142.250.190.46", 443),
                status="ESTABLISHED",
                pid=9999,
            )
        ]
        self.monitor._pid_cache[9999] = "legit_browser.exe"

        res = self.monitor.poll_once()
        self.assertEqual(res["flagged"], 0)
        self.assertTrue(res["is_learning"])

        # Process should be in allowlist now
        self.assertTrue(self.storage.is_process_allowed("legit_browser.exe"))

    @patch("sentinel.monitor.network.get_idle_seconds", return_value=10.0)
    @patch("psutil.net_connections")
    def test_alert_mode_flags_unauthorized_process(self, mock_net, mock_idle):
        # Disable learning mode
        self.storage.disable_learning_mode()
        self.assertFalse(self.storage.is_learning_mode_active())

        # Process not in allowlist
        mock_net.return_value = [
            MockConn(
                fd=-1,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                laddr=MockAddr("192.168.1.50", 49153),
                raddr=MockAddr("203.0.113.5", 4444),
                status="ESTABLISHED",
                pid=8888,
            )
        ]
        self.monitor._pid_cache[8888] = "suspicious_tool.exe"

        res = self.monitor.poll_once()
        self.assertEqual(res["flagged"], 1)

        alerts = self.storage.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "network_unauthorized")
        self.assertEqual(alerts[0]["target_item"], "suspicious_tool.exe")
        self.assertEqual(alerts[0]["remote_ip"], "203.0.113.5")

    @patch("sentinel.monitor.network.get_idle_seconds", return_value=350.0)  # Idle > 100s
    @patch("psutil.net_connections")
    def test_idle_anomaly_detection(self, mock_net, mock_idle):
        # Allow process in baseline
        self.storage.disable_learning_mode()
        self.storage.add_allowlist_entry("background_agent.exe")

        mock_net.return_value = [
            MockConn(
                fd=-1,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                laddr=MockAddr("192.168.1.50", 49154),
                raddr=MockAddr("198.51.100.22", 443),
                status="ESTABLISHED",
                pid=7777,
            )
        ]
        self.monitor._pid_cache[7777] = "background_agent.exe"

        res = self.monitor.poll_once()
        # Should flag because user is idle and external connection is established
        self.assertEqual(res["flagged"], 1)
        alerts = self.storage.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "network_idle")


if __name__ == "__main__":
    unittest.main()
