"""Phase 2: System Change Detector (Autostart entries, Services, Scheduled Tasks)."""

from __future__ import annotations
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.platform_utils import os_system
from sentinel.platform_utils.notifier import Notifier
from sentinel.status_bridge import update_status
from sentinel.utils import logger


class SystemChangeDetector:
    def __init__(self, config: SentinelConfig, storage: Storage, notifier: Notifier):
        self.config = config
        self.storage = storage
        self.notifier = notifier
        self._last_check_time: float = 0.0

    def check_changes(self, force: bool = False) -> Dict[str, Any]:
        """Perform snapshot check across startup items, services, and scheduled tasks.
        Returns summary of inspected and changed items.
        """
        now = time.time()
        if not force and (now - self._last_check_time < self.config.snapshot_interval_seconds):
            return {"status": "skipped_interval", "new_items": 0}

        self._last_check_time = now
        now_iso = datetime.now(timezone.utc).isoformat()

        results = {
            "startup": self._check_category("startup", os_system.collect_startup_items(), now_iso),
            "service": self._check_category("service", os_system.collect_services(), now_iso),
            "scheduled_task": self._check_category("scheduled_task", os_system.collect_scheduled_tasks(), now_iso),
        }

        total_new = sum(len(r["new"]) for r in results.values())
        total_modified = sum(len(r["modified"]) for r in results.values())

        return {
            "status": "checked",
            "new_items": total_new,
            "modified_items": total_modified,
            "details": results,
        }

    def _check_category(
        self,
        category: str,
        current_items: List[Dict[str, Any]],
        timestamp: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        previous_snapshot = self.storage.get_latest_system_snapshot(category)

        new_items: List[Dict[str, Any]] = []
        modified_items: List[Dict[str, Any]] = []

        if not previous_snapshot:
            # First-ever snapshot: establish baseline
            logger.info(f"Establishing baseline for {category} ({len(current_items)} items found)")
            self.storage.record_system_snapshot(category, current_items, timestamp=timestamp)
            return {"new": [], "modified": [], "baseline_count": len(current_items)}

        # Compare against previous snapshot
        current_keys = set()
        for item in current_items:
            key = item["item_key"]
            current_keys.add(key)
            if key not in previous_snapshot:
                new_items.append(item)
            else:
                prev = previous_snapshot[key]
                if item.get("hash") != prev.get("hash") or item.get("item_path") != prev.get("item_path"):
                    modified_items.append({"current": item, "previous": prev})

        # Save new snapshot generation
        self.storage.record_system_snapshot(category, current_items, timestamp=timestamp)

        # Handle alerts for new entries
        category_titles = {
            "startup": "New Startup / Autostart Entry",
            "service": "New System Service",
            "scheduled_task": "New Scheduled Task",
        }
        title = category_titles.get(category, f"New {category}")

        for item in new_items:
            key = item["item_key"]
            path = item.get("item_path", "")
            msg = f"Detected unexpected new item: {key} -> {path}"
            logger.alert(f"{title}: {msg}")

            self.storage.record_alert(
                alert_type=f"system_new_{category}",
                severity="critical" if category == "startup" else "high",
                target_item=key,
                message=msg,
                notified=self.config.notification_enabled,
            )
            update_status(self.storage.db_path)

            self.notifier.notify(
                title=f"Sentinel Alert: {title}",
                message=f"{key}\nTarget: {path}",
                alert_key=f"sys:{category}:{key}",
                severity="high",
            )

        for mod in modified_items:
            item = mod["current"]
            key = item["item_key"]
            path = item.get("item_path", "")
            prev_path = mod["previous"].get("item_path", "")
            msg = f"System item modified: {key} changed from '{prev_path}' to '{path}'"
            logger.alert(f"Modified {category}: {msg}")

            self.storage.record_alert(
                alert_type=f"system_modified_{category}",
                severity="high",
                target_item=key,
                message=msg,
                notified=self.config.notification_enabled,
            )
            update_status(self.storage.db_path)

            self.notifier.notify(
                title=f"Sentinel Alert: Modified {category}",
                message=f"{key} was modified\nNew: {path}",
                alert_key=f"sys_mod:{category}:{key}",
                severity="high",
            )

        return {"new": new_items, "modified": modified_items}
