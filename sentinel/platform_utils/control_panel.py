"""Simple Sentinel control panel GUI.

Provides:
- Start / Stop monitoring
- Allowlist management
- Notification controls
- Settings
- Process priority optimization
"""

from __future__ import annotations
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from sentinel.config import SentinelConfig
    from sentinel.db.storage import Storage
    from sentinel.monitor.network import NetworkMonitor
    from sentinel.monitor.system_change import SystemChangeDetector
    from sentinel.platform_utils.notifier import Notifier
    from sentinel.platform_utils.optimizer import optimize_now
    from sentinel.platform_utils.apps import get_running_apps, get_installed_apps
    from sentinel.utils.priority import set_low_priority
except Exception:
    pass

DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"
DB_PATH = DASHBOARD_DIR.parent / "sentinel.db"


class ControlPanel(QWidget):
    def __init__(self, db_path: Optional[str] = None) -> None:
        super().__init__()
        self.db_path = str(Path(db_path or DB_PATH).resolve())
        self.config = SentinelConfig.load()
        self.storage = Storage(self.db_path)
        self.notifier = Notifier(
            cooldown_seconds=self.config.notification_cooldown_seconds,
            enabled=self.config.notification_enabled,
        )
        self.net_monitor: Optional[NetworkMonitor] = None
        self.sys_detector: Optional[SystemChangeDetector] = None
        self._running = False

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setFixedSize(420, 520)
        self._build_ui()
        self._refresh_status()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("Sentinel Control Panel")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffcc;")
        layout.addWidget(title)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        tabs.addTab(self._build_control_tab(), "Control")
        tabs.addTab(self._build_allowlist_tab(), "Allowlist")
        tabs.addTab(self._build_notifications_tab(), "Notifications")
        tabs.addTab(self._build_settings_tab(), "Settings")

    def _build_control_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        self.status_label = QLabel("Status: Stopped")
        self.status_label.setStyleSheet("color: #ff4444;")
        layout.addWidget(self.status_label)

        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.setStyleSheet("background-color: #1a3a2a; color: #00ffcc; padding: 8px;")
        self.start_btn.clicked.connect(self._start_monitoring)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.setStyleSheet("background-color: #3a1a1a; color: #ff4444; padding: 8px;")
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)

        optimize_btn = QPushButton("Optimize Now")
        optimize_btn.setStyleSheet("background-color: #1a2a3a; color: #ffaa00; padding: 8px;")
        optimize_btn.clicked.connect(self._run_optimize)
        layout.addWidget(optimize_btn)

        self.optimize_output = QTextEdit()
        self.optimize_output.setReadOnly(True)
        self.optimize_output.setMaximumHeight(140)
        layout.addWidget(self.optimize_output)

        layout.addStretch()
        return w

    def _build_allowlist_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        layout.addWidget(QLabel("Running / Installed Applications"))

        self.app_list = QListWidget()
        layout.addWidget(self.app_list)

        add_layout = QHBoxLayout()
        self.app_input = QLineEdit()
        self.app_input.setPlaceholderText("Process name, e.g. chrome.exe")
        add_layout.addWidget(self.app_input)
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._add_allowlist)
        add_layout.addWidget(add_btn)
        layout.addLayout(add_layout)

        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._remove_allowlist)
        layout.addWidget(remove_btn)

        self._refresh_allowlist()
        return w

    def _build_notifications_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        self.notify_checkbox = QCheckBox("Enable Desktop Notifications")
        self.notify_checkbox.setChecked(self.config.notification_enabled)
        self.notify_checkbox.toggled.connect(self._save_notification_setting)
        layout.addWidget(self.notify_checkbox)

        test_btn = QPushButton("Send Test Notification")
        test_btn.clicked.connect(self._test_notification)
        layout.addWidget(test_btn)

        layout.addStretch()
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        layout.addWidget(QLabel("Poll Interval (seconds)"))
        self.poll_spin = QDoubleSpinBox()
        self.poll_spin.setRange(1.0, 60.0)
        self.poll_spin.setValue(self.config.poll_interval_seconds)
        layout.addWidget(self.poll_spin)

        layout.addWidget(QLabel("Snapshot Interval (seconds)"))
        self.snapshot_spin = QDoubleSpinBox()
        self.snapshot_spin.setRange(30.0, 3600.0)
        self.snapshot_spin.setValue(self.config.snapshot_interval_seconds)
        layout.addWidget(self.snapshot_spin)

        layout.addWidget(QLabel("Learning Mode Days"))
        self.learning_spin = QDoubleSpinBox()
        self.learning_spin.setRange(0.0, 30.0)
        self.learning_spin.setValue(self.config.learning_mode_days)
        layout.addWidget(self.learning_spin)

        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self._save_settings)
        layout.addWidget(save_btn)

        layout.addStretch()
        return w

    def _refresh_status(self) -> None:
        try:
            stats = self.storage.get_stats()
            learning = stats.get("is_learning_mode_active")
            if learning:
                self.status_label.setText("Status: Learning Mode")
                self.status_label.setStyleSheet("color: #ffaa00;")
            else:
                self.status_label.setText("Status: Monitoring Active")
                self.status_label.setStyleSheet("color: #00ffcc;")
        except Exception:
            self.status_label.setText("Status: Stopped")
            self.status_label.setStyleSheet("color: #ff4444;")

    def _refresh_allowlist(self) -> None:
        self.app_list.clear()
        try:
            entries = self.storage.get_allowlist()
            for e in entries:
                item = QListWidgetItem(
                    f"{e['process_name']}  |  {e.get('executable_path', '')}"
                )
                item.setData(Qt.ItemDataRole.UserRole, e["process_name"])
                self.app_list.addItem(item)
        except Exception:
            pass

        try:
            apps = get_running_apps() + get_installed_apps()
            seen = set()
            for a in apps:
                name = a.get("name", "")
                if not name or name.lower() in seen:
                    continue
                seen.add(name.lower())
                item = QListWidgetItem(
                    f"[{a.get('status', '')}] {name}  |  {a.get('executable_path', '')}"
                )
                item.setData(Qt.ItemDataRole.UserRole, name)
                self.app_list.addItem(item)
        except Exception:
            pass

    def _add_allowlist(self) -> None:
        name = self.app_input.text().strip()
        if not name:
            return
        try:
            self.storage.add_allowlist_entry(name, manual=True)
            self.app_input.clear()
            self._refresh_allowlist()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _remove_allowlist(self) -> None:
        item = self.app_list.currentItem()
        if not item:
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        try:
            self.storage.remove_allowlist_entry(name)
            self._refresh_allowlist()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _save_notification_setting(self, checked: bool) -> None:
        try:
            self.config.notification_enabled = checked
            self.notifier = Notifier(
                cooldown_seconds=self.config.notification_cooldown_seconds,
                enabled=checked,
            )
        except Exception:
            pass

    def _test_notification(self) -> None:
        try:
            self.notifier.notify(
                title="Sentinel Test",
                message="Notifications are working!",
                alert_key="test",
                severity="medium",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _save_settings(self) -> None:
        try:
            self.config.poll_interval_seconds = self.poll_spin.value()
            self.config.snapshot_interval_seconds = self.snapshot_spin.value()
            self.config.learning_mode_days = self.learning_spin.value()
            QMessageBox.information(self, "Settings", "Settings saved.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _start_monitoring(self) -> None:
        try:
            set_low_priority()
            self.net_monitor = NetworkMonitor(self.config, self.storage, self.notifier)
            self.sys_detector = SystemChangeDetector(self.config, self.storage, self.notifier)
            self._running = True
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self._refresh_status()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _stop_monitoring(self) -> None:
        self._running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._refresh_status()

    def _run_optimize(self) -> None:
        try:
            result = optimize_now(aggressive=False)
            lines = [f"Optimized at {result['timestamp']}"]
            for r in result.get("results", []):
                lines.append(f"  {r['name']} (PID {r['pid']}): {r['action']}")
            self.optimize_output.setText("\n".join(lines))
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))


def run_control_panel(db_path: Optional[str] = None) -> None:
    app = QApplication(sys.argv)
    widget = ControlPanel(db_path=db_path)
    widget.show()
    sys.exit(app.exec())
