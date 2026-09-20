"""Cross-platform desktop notification dispatcher with rate-limiting and fallbacks."""

from __future__ import annotations
import shutil
import subprocess
import sys
import threading
import time
from typing import Dict, Optional
from sentinel.utils import logger


class Notifier:
    def __init__(self, cooldown_seconds: float = 60.0, enabled: bool = True):
        self.cooldown_seconds = cooldown_seconds
        self.enabled = enabled
        self._last_alert_times: Dict[str, float] = {}
        self._lock = threading.Lock()

    def should_notify(self, alert_key: str) -> bool:
        if not self.enabled:
            return False
        now = time.time()
        with self._lock:
            last = self._last_alert_times.get(alert_key, 0.0)
            if now - last < self.cooldown_seconds:
                return False
            self._last_alert_times[alert_key] = now
            return True

    def notify(
        self,
        title: str,
        message: str,
        alert_key: Optional[str] = None,
        severity: str = "medium",
    ) -> bool:
        """Send desktop notification. Asynchronous, never blocks caller."""
        # Print to console immediately
        logger.alert(f"{title}: {message}")

        if alert_key and not self.should_notify(alert_key):
            logger.debug(f"Notification for '{alert_key}' suppressed by cooldown ({self.cooldown_seconds}s)")
            return False

        if not self.enabled:
            return False

        # Dispatch async notification
        t = threading.Thread(
            target=self._dispatch_notification,
            args=(title, message, severity),
            daemon=True,
        )
        t.start()
        return True

    def _dispatch_notification(self, title: str, message: str, severity: str) -> None:
        try:
            if sys.platform == "win32":
                self._notify_windows(title, message)
            elif sys.platform == "darwin":
                self._notify_macos(title, message)
            else:
                self._notify_linux(title, message)
        except Exception as e:
            logger.debug(f"Desktop notification failed: {e}")

    def _notify_windows(self, title: str, message: str) -> None:
        # Tier 1: Try win11toast
        try:
            import win11toast
            win11toast.notify(title, message, app_id="Sentinel Security Monitor")
            return
        except Exception:
            pass

        # Tier 2: Try plyer
        try:
            from plyer import notification
            notification.notify(
                title=title,
                message=message,
                app_name="Sentinel",
                timeout=5,
            )
            return
        except Exception:
            pass

        # Tier 3: PowerShell fallback
        try:
            escaped_title = title.replace("'", "''")
            escaped_msg = message.replace("'", "''")
            ps_cmd = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $textNodes = $template.GetElementsByTagName('text')
            $textNodes.Item(0).AppendChild($template.CreateTextNode('{escaped_title}')) | Out-Null
            $textNodes.Item(1).AppendChild($template.CreateTextNode('{escaped_msg}')) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
            $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Sentinel')
            $notifier.Show($toast)
            """
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, timeout=5.0)
        except Exception:
            pass

    def _notify_macos(self, title: str, message: str) -> None:
        # Tier 1: AppleScript
        try:
            escaped_msg = message.replace('"', '\\"')
            escaped_title = title.replace('"', '\\"')
            script = f'display notification "{escaped_msg}" with title "{escaped_title}"'
            res = subprocess.run(["osascript", "-e", script], capture_output=True, timeout=3.0)
            if res.returncode == 0:
                return
        except Exception:
            pass

        # Tier 2: plyer
        try:
            from plyer import notification
            notification.notify(title=title, message=message, app_name="Sentinel", timeout=5)
        except Exception:
            pass

    def _notify_linux(self, title: str, message: str) -> None:
        # Tier 1: notify-send
        if shutil.which("notify-send"):
            try:
                subprocess.run(["notify-send", title, message, "-a", "Sentinel"], timeout=3.0)
                return
            except Exception:
                pass

        # Tier 2: plyer
        try:
            from plyer import notification
            notification.notify(title=title, message=message, app_name="Sentinel", timeout=5)
        except Exception:
            pass
