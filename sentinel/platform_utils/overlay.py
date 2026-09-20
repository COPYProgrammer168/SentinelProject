"""Always-on-top alert overlay widget for Sentinel.

Compact state: 320x180px alert feed.
Expanded state: 500x400px with traffic graph, world map, attack/crack counters.
"""

from __future__ import annotations
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import ipaddress

from PyQt6.QtCore import QPoint, QRectF, QSize, QTimer, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PyQt6.QtWidgets import QApplication, QLabel, QMenu, QWidget

DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"
DB_PATH = DASHBOARD_DIR.parent / "sentinel.db"

WORLD_MAP_SVG = """
<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1000 500'>
  <rect width='1000' height='500' fill='#0a0e14'/>
  <g fill='#1e2833' stroke='#1e2833' stroke-width='0.5'>
    <path d='M180,120 Q220,100 260,120 T340,120 T420,120 T500,120 T580,120 T660,120 T740,120 T820,120 Q860,100 900,120 L900,180 Q860,160 820,180 T740,180 T660,180 T580,180 T500,180 T420,180 T340,180 T260,180 T180,180 Z'/>
    <path d='M180,220 Q220,200 260,220 T340,220 T420,220 T500,220 T580,220 T660,220 T740,220 T820,220 Q860,200 900,220 L900,280 Q860,260 820,280 T740,280 T660,280 T580,280 T500,280 T420,280 T340,280 T260,280 T180,280 Z'/>
    <path d='M180,320 Q220,300 260,320 T340,320 T420,320 T500,320 T580,320 T660,320 T740,320 T820,320 Q860,300 900,320 L900,380 Q860,360 820,380 T740,380 T660,380 T580,380 T500,380 T420,380 T340,380 T260,380 T180,380 Z'/>
  </g>
</svg>
"""


def ip_to_xy(ip: str) -> Optional[tuple]:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
        parts = str(addr).split(".")
        if len(parts) != 4:
            return None
        x = int(parts[0]) / 255.0 * 1000
        y = (255 - int(parts[1])) / 255.0 * 500
        return (x, y)
    except Exception:
        return None


class OverlayWidget(QWidget):
    def __init__(self, db_path: Optional[str] = None) -> None:
        super().__init__()
        self.db_path = str(Path(db_path or DB_PATH).resolve())
        self._expanded = False
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setStyleSheet("background-color: #0a0e14;")
        self.resize(320, 180)
        self._load_position()
        self._alerts: List[Dict[str, Any]] = []
        self._flash_count = 0
        self._flash_state = False
        self._traffic_data: List[tuple] = []
        self._attack_counts: Dict[str, int] = {}
        self._crack_count = 0
        self._map_dots: List[tuple] = []

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_data)
        self._poll_timer.start(2000)

        self._flash_timer = QTimer(self)
        self._flash_timer.timeout.connect(self._update_flash)
        self._flash_timer.start(150)

        self._poll_data()

    def _load_position(self) -> None:
        try:
            pos_file = DASHBOARD_DIR / "overlay_position.json"
            if pos_file.is_file():
                data = json.loads(pos_file.read_text(encoding="utf-8"))
                self.move(data.get("x", 0), data.get("y", 0))
                return
        except Exception:
            pass
        screen = QApplication.primaryScreen().availableGeometry()
        self.move(screen.width() - self.width() - 20, 20)

    def _save_position(self) -> None:
        try:
            pos_file = DASHBOARD_DIR / "overlay_position.json"
            pos_file.write_text(json.dumps({"x": self.x(), "y": self.y()}), encoding="utf-8")
        except Exception:
            pass

    def _write_status_file(self) -> None:
        try:
            status = {
                "alerts_count": len(self._alerts),
                "critical_count": sum(1 for a in self._alerts if (a.get("severity") or "").lower() == "critical"),
                "last_alert": self._alerts[0].get("alert_type") if self._alerts else None,
                "traffic_count": sum(v for _, v in self._traffic_data),
                "crack_count": self._crack_count,
                "updated": datetime.now(timezone.utc).isoformat(),
            }
            status_file = DASHBOARD_DIR / "overlay_status.json"
            status_file.write_text(json.dumps(status), encoding="utf-8")
        except Exception:
            pass

    def _poll_data(self) -> None:
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            now = datetime.now(timezone.utc)
            cutoff = (now - timedelta(minutes=30)).isoformat()
            rows = conn.execute(
                "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY id DESC LIMIT 5",
                (cutoff,),
            ).fetchall()
            self._alerts = [dict(r) for r in rows]

            traffic_rows = conn.execute(
                "SELECT timestamp FROM network_events WHERE timestamp >= ? ORDER BY timestamp ASC",
                ((now - timedelta(minutes=5)).isoformat(),),
            ).fetchall()
            buckets: Dict[str, int] = {}
            for r in traffic_rows:
                ts = r["timestamp"][:13]
                buckets[ts] = buckets.get(ts, 0) + 1
            self._traffic_data = sorted(buckets.items())

            crit_rows = conn.execute(
                "SELECT alert_type, COUNT(*) as cnt FROM alerts WHERE severity='critical' AND timestamp >= ? GROUP BY alert_type",
                (cutoff,),
            ).fetchall()
            self._attack_counts = {r["alert_type"]: r["cnt"] for r in crit_rows}

            crack_rows = conn.execute(
                "SELECT COUNT(*) as cnt FROM flagged_software WHERE first_seen >= ?",
                (cutoff,),
            ).fetchall()
            self._crack_count = crack_rows[0]["cnt"] if crack_rows else 0

            map_rows = conn.execute(
                "SELECT remote_ip, is_flagged FROM network_events WHERE timestamp >= ? AND remote_ip != '' GROUP BY remote_ip",
                (cutoff,),
            ).fetchall()
            dots = []
            for r in map_rows:
                xy = ip_to_xy(r["remote_ip"])
                if xy:
                    dots.append((xy[0], xy[1], bool(r["is_flagged"])))
            self._map_dots = dots

            self._write_status_file()
            conn.close()
            self.update()
        except Exception:
            pass

    def _update_flash(self) -> None:
        if self._flash_count > 0:
            self._flash_state = not self._flash_state
            self._flash_count -= 1
            self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QColor("#0a0e14")
        painter.fillRect(self.rect(), bg)
        border_color = QColor("#ff4444") if self._flash_state else QColor("#00ffcc")
        pen = QPen(border_color)
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawRect(self.rect().adjusted(1, 1, -1, -1))

        if self._expanded:
            self._paint_expanded(painter)
        else:
            self._paint_compact(painter)

    def _paint_compact(self, painter: QPainter) -> None:
        painter.setPen(QColor("#c5c8c6"))
        font = QFont("Consolas", 9)
        painter.setFont(font)
        y = 15
        for alert in self._alerts[:5]:
            ts = (alert.get("timestamp") or "")[11:19]
            proc = alert.get("target_item", "")
            atype = alert.get("alert_type", "")
            text = f"[{ts}] {proc} -> {atype}"
            severity = (alert.get("severity") or "").lower()
            if severity == "critical":
                painter.setPen(QColor("#ff4444"))
            elif severity == "log_only":
                painter.setPen(QColor("#ffaa00"))
            else:
                painter.setPen(QColor("#00ffcc"))
            painter.drawText(10, y, text)
            y += 22
        if not self._alerts:
            painter.setPen(QColor("#8b949e"))
            painter.drawText(10, 20, "No recent alerts")

    def _paint_expanded(self, painter: QPainter) -> None:
        w, h = self.width(), self.height()

        # Attack counters row
        counter_y = 10
        painter.setPen(QColor("#00ffcc"))
        painter.setFont(QFont("Consolas", 8))
        brute = self._attack_counts.get("bruteforce", 0)
        portscan = self._attack_counts.get("portscan", 0)
        unknown = self._attack_counts.get("network_unauthorized", 0)
        painter.drawText(10, counter_y, f"Brute-force: {brute}  Port scans: {portscan}  Unknown: {unknown}  Crack: {self._crack_count} (heuristic)")

        # Traffic graph
        graph_y = 30
        graph_h = 120
        painter.fillRect(10, graph_y, w - 20, graph_h, QColor("#11161d"))
        painter.setPen(QColor("#1e2833"))
        painter.drawRect(10, graph_y, w - 20, graph_h)
        if len(self._traffic_data) > 1:
            painter.setPen(QPen(QColor("#00ffcc"), 2))
            vals = [v for _, v in self._traffic_data]
            max_v = max(vals) if vals else 1
            points = []
            for i, (ts, v) in enumerate(self._traffic_data):
                x = 10 + (i / max(len(vals) - 1, 1)) * (w - 20)
                y = graph_y + graph_h - (v / max_v) * graph_h
                points.append(QPointF(x, y))
            if len(points) > 1:
                poly = QPolygonF(points)
                painter.drawPolyline(poly)
        painter.setPen(QColor("#8b949e"))
        painter.setFont(QFont("Consolas", 7))
        painter.drawText(10, graph_y + graph_h + 12, "Active connections (last 5 min)")

        # Map area
        map_y = graph_y + graph_h + 20
        map_h = h - map_y - 10
        painter.fillRect(10, map_y, w - 20, map_h, QColor("#11161d"))
        painter.setPen(QColor("#1e2833"))
        painter.drawRect(10, map_y, w - 20, map_h)
        painter.setPen(QColor("#8b949e"))
        painter.drawText(15, map_y + 12, "Approximate — VPN/proxy use will misrepresent location")
        for x, y, flagged in self._map_dots:
            color = QColor("#ff4444") if flagged else QColor("#00ffcc")
            painter.setPen(QPen(color, 3))
            painter.drawPoint(int(10 + x / 1000 * (w - 20)), int(map_y + 20 + y / 500 * (map_h - 30)))

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.pos()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if hasattr(self, "_drag_start"):
            delta = event.pos() - self._drag_start
            self.move(self.pos() + delta)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._save_position()
        delattr(self, "_drag_start")

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802
        self._expanded = not self._expanded
        if self._expanded:
            self.resize(500, 400)
        else:
            self.resize(320, 180)
        self.update()

    def contextMenuEvent(self, event) -> None:  # noqa: N802
        menu = QMenu(self)
        hide_action = menu.addAction("Hide")
        pin_action = menu.addAction("Unpin from top" if self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint else "Pin on top")
        quit_action = menu.addAction("Quit")
        action = menu.exec(self.mapToGlobal(event.pos()))
        if action == hide_action:
            self.hide()
        elif action == pin_action:
            if self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint:
                self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
            else:
                self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
            self.show()
        elif action == quit_action:
            QApplication.quit()

    def flash_critical(self) -> None:
        self._flash_count = 4
        self._flash_state = True
        self.update()


def run_overlay(db_path: Optional[str] = None) -> None:
    app = QApplication(sys.argv)
    widget = OverlayWidget(db_path=db_path)
    widget.show()
    sys.exit(app.exec())
