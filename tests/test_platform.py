"""Test suite for platform utilities (idle detection, OS collectors, notifier)."""

import unittest
from sentinel.platform_utils import idle, os_system
from sentinel.platform_utils.notifier import Notifier


class TestPlatformUtils(unittest.TestCase):
    def test_idle_detection(self):
        seconds = idle.get_idle_seconds()
        self.assertIsInstance(seconds, float)
        self.assertGreaterEqual(seconds, 0.0)

    def test_os_collectors(self):
        # Startup items
        startup = os_system.collect_startup_items()
        self.assertIsInstance(startup, list)
        for item in startup:
            self.assertIn("item_key", item)
            self.assertIn("hash", item)

        # Services
        services = os_system.collect_services()
        self.assertIsInstance(services, list)
        self.assertGreater(len(services), 0)
        for s in services[:5]:
            self.assertIn("item_key", s)
            self.assertIn("hash", s)

        # Scheduled tasks
        tasks = os_system.collect_scheduled_tasks()
        self.assertIsInstance(tasks, list)
        for t in tasks[:5]:
            self.assertIn("item_key", t)
            self.assertIn("hash", t)

    def test_notifier_cooldown(self):
        notifier = Notifier(cooldown_seconds=10.0, enabled=True)
        self.assertTrue(notifier.should_notify("key1"))
        # Immediate second call with same key should be suppressed by cooldown
        self.assertFalse(notifier.should_notify("key1"))
        # Different key should pass
        self.assertTrue(notifier.should_notify("key2"))

    def test_autostart_toggle(self):
        from sentinel.platform_utils import autostart
        initial_state = autostart.is_autostart_enabled()
        # Test enable
        self.assertTrue(autostart.enable_autostart())
        self.assertTrue(autostart.is_autostart_enabled())
        # Test disable
        self.assertTrue(autostart.disable_autostart())
        self.assertFalse(autostart.is_autostart_enabled())
        # Restore initial state if it was enabled
        if initial_state:
            autostart.enable_autostart()


if __name__ == "__main__":
    unittest.main()
