"""Tests for attack-severity classification."""

import unittest
from sentinel.severity import SeverityClassifier, classify_network_event, classify_system_change
from datetime import datetime, timezone


class TestSeverityClassifier(unittest.TestCase):
    def setUp(self):
        self.clf = SeverityClassifier()

    def test_unknown_process_is_critical(self):
        severity, _ = self.clf.classify_network(
            alert_type="network_unauthorized",
            process_name="unknown.exe",
            remote_ip="1.2.3.4",
            remote_port=443,
            is_idle=False,
            signer="",
            is_process_allowed=False,
            severity="high",
        )
        self.assertEqual(severity, "CRITICAL")

    def test_trusted_process_is_log_only(self):
        severity, _ = self.clf.classify_network(
            alert_type="network_trusted_unrecognized",
            process_name="OneDrive.exe",
            remote_ip="1.2.3.4",
            remote_port=443,
            is_idle=False,
            signer="Microsoft Corporation",
            is_process_allowed=True,
            severity="low",
        )
        self.assertEqual(severity, "LOG_ONLY")

    def test_port_scan_triggers_critical(self):
        ip = "192.168.1.100"
        for port in [21, 22, 23, 25, 80]:
            severity, _ = self.clf.classify_network(
                alert_type="network_unauthorized",
                process_name="scanner.exe",
                remote_ip=ip,
                remote_port=port,
                is_idle=False,
                signer="",
                is_process_allowed=False,
                severity="low",
            )
        self.assertEqual(severity, "CRITICAL")

    def test_sensitive_port_from_unknown_is_critical(self):
        severity, _ = self.clf.classify_network(
            alert_type="network_unauthorized",
            process_name="unknown.exe",
            remote_ip="5.6.7.8",
            remote_port=22,
            is_idle=False,
            signer="",
            is_process_allowed=False,
            severity="low",
        )
        self.assertEqual(severity, "CRITICAL")

    def test_sensitive_port_from_known_is_log_only(self):
        self.clf.known_ips.add("5.6.7.8")
        severity, _ = self.clf.classify_network(
            alert_type="network_trusted_unrecognized",
            process_name="trusted.exe",
            remote_ip="5.6.7.8",
            remote_port=3389,
            is_idle=False,
            signer="Trusted Publisher",
            is_process_allowed=True,
            severity="low",
        )
        self.assertEqual(severity, "LOG_ONLY")

    def test_unsigned_idle_process_is_critical(self):
        severity, _ = self.clf.classify_network(
            alert_type="network_unauthorized",
            process_name="mystery.exe",
            remote_ip="9.10.11.12",
            remote_port=443,
            is_idle=True,
            signer="",
            is_process_allowed=False,
            severity="low",
        )
        self.assertEqual(severity, "CRITICAL")

    def test_system_change_new_admin_account_is_critical(self):
        self.clf.known_admin_accounts.add("Administrator")
        severity, _ = self.clf.classify_system({
            "category": "user_account",
            "item_key": "Administrator",
            "item_path": "",
            "item_state": "new",
        })
        self.assertEqual(severity, "CRITICAL")

    def test_system_change_firewall_disabled_is_critical(self):
        severity, _ = self.clf.classify_system({
            "category": "firewall",
            "item_key": "FirewallRule",
            "item_path": "",
            "item_state": "disabled",
        })
        self.assertEqual(severity, "CRITICAL")

    def test_system_change_sentinel_stopped_is_critical(self):
        severity, _ = self.clf.classify_system({
            "category": "service",
            "item_key": "SentinelMonitor",
            "item_path": "sentinel.exe",
            "item_state": "stopped",
        })
        self.assertEqual(severity, "CRITICAL")

    def test_system_change_regular_startup_is_log_only(self):
        severity, _ = self.clf.classify_system({
            "category": "startup",
            "item_key": "Startup:Chrome",
            "item_path": "C:\\Chrome.exe",
            "item_state": "enabled",
        })
        self.assertEqual(severity, "LOG_ONLY")


if __name__ == "__main__":
    unittest.main()
