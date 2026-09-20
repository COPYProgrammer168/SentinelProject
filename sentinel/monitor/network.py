"""Phase 1: Core Network Monitor with Learning mode baseline and idle anomaly detection."""

from __future__ import annotations
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import psutil
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.platform_utils.idle import get_idle_seconds
from sentinel.platform_utils.notifier import Notifier
from sentinel.platform_utils.signer import get_process_identity
import sentinel.providers as providers
from sentinel.severity import SeverityClassifier
from sentinel.status_bridge import update_status
from sentinel.utils import logger


class NetworkMonitor:
    def __init__(self, config: SentinelConfig, storage: Storage, notifier: Notifier):
        self.config = config
        self.storage = storage
        self.notifier = notifier
        self._pid_cache: Dict[int, str] = {}
        self._active_connections: Dict[Tuple[int, str, int, str, str], float] = {}
        self._last_provider_refresh: float = 0.0
        self._severity_classifier = SeverityClassifier()

    def _get_process_name(self, pid: Optional[int]) -> str:
        if pid is None or pid < 0:
            return "unknown"
        if pid == 0:
            return "System Idle"
        if pid == 4:
            return "System"
        if pid in self._pid_cache:
            return self._pid_cache[pid]
        try:
            p = psutil.Process(pid)
            name = p.name()
            self._pid_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "unknown"

    def _is_loopback(self, ip: str) -> bool:
        if not ip:
            return True
        if ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::"):
            return True
        if ip.startswith("127."):
            return True
        return False

    def _refresh_provider_cidrs_if_needed(self) -> None:
        now = time.time()
        if now - self._last_provider_refresh > 3600.0:
            try:
                providers.refresh_provider_cidrs(force=False)
            except Exception:
                pass
            self._last_provider_refresh = now

    def _check_provider_cidr(self, remote_ip: str) -> Optional[str]:
        """Check if IP is in a trusted provider range. Returns provider name or None."""
        self._refresh_provider_cidrs_if_needed()
        return providers.is_ip_in_trusted_range(remote_ip)

    def poll_once(self) -> Dict[str, Any]:
        """Perform one poll cycle of active network connections."""
        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        now_ts = time.time()

        is_learning = self.storage.is_learning_mode_active()
        idle_sec = get_idle_seconds()
        is_user_idle = idle_sec >= self.config.idle_threshold_seconds

        events_to_log: List[Dict[str, Any]] = []
        flagged_count = 0
        total_connections = 0

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.warn(f"Failed to fetch net_connections: {e}")
            return {"total": 0, "flagged": 0, "is_learning": is_learning}

        total_connections = len(connections)

        for conn in connections:
            pid = conn.pid
            proc_name = self._get_process_name(pid)
            status = conn.status or "NONE"
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            local_ip = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            proc_identity = get_process_identity(pid) if proc_name and proc_name != "unknown" else {}
            exe_path = proc_identity.get("executable_path", "")
            signer = proc_identity.get("signer", "")
            file_hash = proc_identity.get("file_hash", "")

            if proc_name and proc_name != "unknown":
                self.storage.record_process_observed(
                    proc_name,
                    is_learning_mode=is_learning,
                    executable_path=exe_path,
                    signer=signer,
                    file_hash=file_hash,
                )

            is_remote_external = bool(remote_ip) and not self._is_loopback(remote_ip)

            is_flagged = False
            flag_reasons: List[str] = []
            alert_type = ""
            severity = "low"
            notify = False
            alert_key = ""

            if not is_learning and proc_name and proc_name != "unknown":
                if is_remote_external and not self.storage.is_process_allowed(
                    proc_name,
                    executable_path=exe_path,
                    signer=signer,
                ):
                    is_flagged = True
                    flag_reasons.append(f"Unrecognized process '{proc_name}' (not in baseline allowlist)")
                    alert_type = "network_unauthorized"
                    severity = "high"
                    notify = True
                    alert_key = f"{proc_name}:{remote_ip}"
                else:
                    provider = self._check_provider_cidr(remote_ip) if is_remote_external else None
                    if provider:
                        pass
                    elif is_remote_external:
                        is_flagged = True
                        flag_reasons.append(f"Trusted process '{proc_name}', unrecognized destination {remote_ip}")
                        alert_type = "network_trusted_unrecognized"
                        severity = "low"
                        notify = False
                        alert_key = f"{proc_name}:{remote_ip}"

            if (
                self.config.idle_network_alert_enabled
                and is_user_idle
                and is_remote_external
                and status in ("ESTABLISHED", "SYN_SENT")
            ):
                idle_mins = int(idle_sec // 60)
                if not is_flagged:
                    is_flagged = True
                    alert_type = "network_idle"
                    severity = "low"
                    notify = False
                    alert_key = f"{proc_name}:{remote_ip}"
                flag_reasons.append(f"Network connection during idle state ({idle_mins}m idle)")

            flag_reason_str = "; ".join(flag_reasons) if is_flagged else ""

            conn_key = (pid or 0, remote_ip, remote_port, protocol, status)
            is_new_conn = conn_key not in self._active_connections or (now_ts - self._active_connections[conn_key] > 60.0)
            self._active_connections[conn_key] = now_ts

            if is_flagged:
                flagged_count += 1
                if not alert_type:
                    alert_type = "network_unauthorized"
                if not severity:
                    severity = "medium"

                classified_severity, rule_label = self._severity_classifier.classify_network(
                    alert_type=alert_type,
                    process_name=proc_name,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    is_idle=is_user_idle,
                    signer=signer,
                    is_process_allowed=bool(
                        proc_name and proc_name != "unknown"
                        and self.storage.is_process_allowed(proc_name, executable_path=exe_path, signer=signer)
                    ),
                    severity=severity,
                )
                if classified_severity == "CRITICAL":
                    severity = "critical"
                    if rule_label and rule_label not in flag_reason_str:
                        flag_reason_str = f"{rule_label}; {flag_reason_str}" if flag_reason_str else rule_label

                identity_key = self.storage._make_alert_identity_key(proc_name, alert_type, remote_ip)
                identity = self.storage.record_alert_identity(
                    proc_name, alert_type, remote_ip, severity, self.config.notification_cooldown_minutes
                )

                should_notify = True
                if severity != "critical" and self.config.notification_cooldown_minutes > 0:
                    if self.storage.is_alert_in_cooldown(identity_key, self.config.notification_cooldown_minutes):
                        should_notify = False
                    elif identity["occurrence_count"] > 1:
                        flag_reason_str += (
                            f" ({identity['occurrence_count']} times in last "
                            f"{self.config.notification_cooldown_minutes} min)"
                        )

                self.storage.record_alert(
                    alert_type=alert_type,
                    severity=severity,
                    target_item=proc_name,
                    remote_ip=remote_ip,
                    message=f"{proc_name} -> {remote_ip}:{remote_port} ({flag_reason_str})",
                    notified=should_notify and self.config.notification_enabled,
                )
                update_status(self.storage.db_path)

                if should_notify:
                    self.storage.record_alert_notification(identity_key)
                    self.notifier.notify(
                        title="Sentinel: Suspicious Network Activity",
                        message=f"[{proc_name}] -> {remote_ip}:{remote_port}\n{flag_reason_str}",
                        alert_key=alert_key,
                        severity=severity,
                    )

            if is_flagged or (self.config.log_all_network_events and is_new_conn):
                events_to_log.append({
                    "timestamp": now_iso,
                    "pid": pid,
                    "process_name": proc_name,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "protocol": protocol,
                    "status": status,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "is_flagged": 1 if is_flagged else 0,
                    "flag_reason": flag_reason_str,
                })

        cutoff = now_ts - 120.0
        self._active_connections = {k: v for k, v in self._active_connections.items() if v > cutoff}

        if events_to_log:
            self.storage.log_network_events(events_to_log)

        return {
            "total_connections": total_connections,
            "flagged": flagged_count,
            "logged_events": len(events_to_log),
            "is_learning": is_learning,
            "idle_seconds": idle_sec,
        }
