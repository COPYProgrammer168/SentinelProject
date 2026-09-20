"""Verification test for the OneDrive false positive fix."""

import os
import socket
import tempfile
import unittest
from unittest.mock import patch
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.monitor.network import NetworkMonitor
from sentinel.platform_utils.notifier import Notifier

MockAddr = __import__("tests.test_network_monitor", fromlist=["MockAddr"]).MockAddr
MockConn = __import__("tests.test_network_monitor", fromlist=["MockConn"]).MockConn


class TestOneDriveScenario(unittest.TestCase):
    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(self.tmp_fd)
        self.config = SentinelConfig(db_path=self.tmp_path, idle_threshold_seconds=100.0)
        self.storage = Storage(self.tmp_path)
        self.notifier = Notifier(enabled=True)
        self.monitor = NetworkMonitor(self.config, self.storage, self.notifier)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except Exception:
                pass

    @patch("sentinel.monitor.network.get_idle_seconds", return_value=10.0)
    @patch("sentinel.providers.is_ip_in_trusted_range")
    @patch("psutil.net_connections")
    def test_onedrive_multiple_ips_no_notifications(self, mock_net, mock_provider, mock_idle):
        """OneDrive connecting to 4 different Microsoft IPs should produce zero real-time notifications."""
        # Learning mode active - OneDrive gets added to allowlist on first sight
        self.storage.init_learning_mode_if_needed(duration_days=7.0)
        self.assertTrue(self.storage.is_learning_mode_active())

        # Mock provider check - all 4 IPs are in Microsoft/Azure range
        mock_provider.return_value = "Microsoft/Azure"

        # Simulate 4 connections from OneDrive to different Microsoft IPs in one minute
        oneDrive_ips = [
            "20.135.6.11",
            "20.209.184.65",
            "13.107.137.11",
            "51.132.193.110",
        ]

        notifications_sent = []
        original_notify = self.notifier.notify

        def capture_notify(title, message, alert_key=None, severity="medium"):
            notifications_sent.append({
                "title": title,
                "message": message,
                "alert_key": alert_key,
                "severity": severity,
            })
            return True

        self.notifier.notify = capture_notify

        for ip in oneDrive_ips:
            mock_net.return_value = [
                MockConn(
                    fd=-1,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                    laddr=MockAddr("192.168.1.50", 49152),
                    raddr=MockAddr(ip, 443),
                    status="ESTABLISHED",
                    pid=9999,
                )
            ]
            self.monitor._pid_cache[9999] = "OneDrive.Sync.Service.exe"
            res = self.monitor.poll_once()

        self.notifier.notify = original_notify

        # Verify: zero notifications sent
        self.assertEqual(len(notifications_sent), 0,
                         f"Expected 0 notifications but got {len(notifications_sent)}: {notifications_sent}")

        # Verify: OneDrive is in allowlist
        self.assertTrue(self.storage.is_process_allowed("OneDrive.Sync.Service.exe"))

        # Verify: no high-severity alerts
        alerts = self.storage.get_recent_alerts(limit=10)
        high_alerts = [a for a in alerts if a["severity"] == "high"]
        self.assertEqual(len(high_alerts), 0,
                         f"Expected 0 high-severity alerts but got {high_alerts}")

    @patch("sentinel.monitor.network.get_idle_seconds", return_value=10.0)
    @patch("sentinel.providers.is_ip_in_trusted_range")
    @patch("psutil.net_connections")
    def test_onedrive_non_provider_ip_low_severity(self, mock_net, mock_provider, mock_idle):
        """OneDrive to non-provider IP should be low severity, then dedup suppresses repeats."""
        self.storage.disable_learning_mode()
        self.storage.add_allowlist_entry("OneDrive.Sync.Service.exe")

        mock_provider.return_value = None  # Not in any provider range

        mock_net.return_value = [
            MockConn(
                fd=-1,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                laddr=MockAddr("192.168.1.50", 49152),
                raddr=MockAddr("203.0.113.5", 443),
                status="ESTABLISHED",
                pid=9999,
            )
        ]
        self.monitor._pid_cache[9999] = "OneDrive.Sync.Service.exe"

        notifications_sent = []
        original_notify = self.notifier.notify
        self.notifier.notify = lambda **kw: notifications_sent.append(kw) or True

        # First occurrence: should notify once (low severity, first time)
        res = self.monitor.poll_once()
        self.assertEqual(res["flagged"], 1)
        self.assertEqual(len(notifications_sent), 1, f"Expected 1 notification on first occurrence, got {len(notifications_sent)}")

        # Second occurrence immediately after: should be deduped (no new notification)
        res2 = self.monitor.poll_once()
        self.assertEqual(res2["flagged"], 1)
        self.assertEqual(len(notifications_sent), 1, f"Expected 1 notification total after dedup, got {len(notifications_sent)}")

        self.notifier.notify = original_notify

        alerts = self.storage.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["severity"], "low")
        self.assertIn("unrecognized destination", alerts[0]["message"])

    @patch("sentinel.monitor.network.get_idle_seconds", return_value=10.0)
    @patch("sentinel.providers.is_ip_in_trusted_range")
    @patch("psutil.net_connections")
    def test_unknown_process_still_flags(self, mock_net, mock_provider, mock_idle):
        """Unknown processes should still generate full alerts."""
        self.storage.disable_learning_mode()

        mock_provider.return_value = None

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

        notifications_sent = []
        original_notify = self.notifier.notify
        self.notifier.notify = lambda **kw: notifications_sent.append(kw) or True

        res = self.monitor.poll_once()

        self.notifier.notify = original_notify

        self.assertEqual(res["flagged"], 1)
        self.assertEqual(len(notifications_sent), 1)
        self.assertEqual(notifications_sent[0].get("severity"), "critical")


if __name__ == "__main__":
    unittest.main()
