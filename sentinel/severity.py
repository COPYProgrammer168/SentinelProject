"""Attack-severity classifier for Sentinel.

Maps detected events to CRITICAL (always notify immediately) or LOG_ONLY
(write to DB / dashboard, no push notification).  All classification
rules live here so they are easy to audit and extend later.
"""

from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

SENSITIVE_PORTS = {22, 3389, 445}
CRITICAL_RULE_LABELS = {
    "bruteforce": "Brute-force attempt",
    "portscan": "Port-scan pattern",
    "sensitive_port": "Sensitive-port probe",
    "unsigned_idle": "Unsigned process active while idle",
    "security_change": "Security-relevant system change",
}


def classify_network_event(
    *,
    alert_type: str,
    process_name: str,
    remote_ip: str,
    remote_port: int,
    is_idle: bool,
    signer: str,
    is_process_allowed: bool,
    severity: str,
    port_scan_tracker: Dict[str, List[Tuple[float, int]]],
    known_ips: Set[str],
    now: Optional[datetime] = None,
) -> Tuple[str, Optional[str]]:
    """Classify a single network event.

    Returns (severity, rule_label) where severity is CRITICAL or LOG_ONLY.
    rule_label is a human-readable explanation when CRITICAL, or None.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    effective_severity = "CRITICAL" if severity == "high" else "LOG_ONLY"
    rule_label = None

    if effective_severity == "CRITICAL":
        return effective_severity, rule_label

    # Rule 2: Port-scan pattern
    if remote_ip:
        events = port_scan_tracker.get(remote_ip, [])
        events = [(ts, p) for ts, p in events if now - datetime.fromtimestamp(ts, tz=timezone.utc) < timedelta(seconds=60)]
        port_scan_tracker[remote_ip] = events
        if remote_port and remote_port not in {p for _, p in events}:
            events.append((now.timestamp(), remote_port))
            port_scan_tracker[remote_ip] = events
        distinct_ports = len({p for _, p in events})
        if distinct_ports >= 5:
            effective_severity = "CRITICAL"
            rule_label = f"{CRITICAL_RULE_LABELS['portscan']} ({distinct_ports} ports in 60s from {remote_ip})"
            return effective_severity, rule_label

    # Rule 4: Sensitive-port probe from unknown source
    if remote_port in SENSITIVE_PORTS and remote_ip not in known_ips:
        effective_severity = "CRITICAL"
        rule_label = f"{CRITICAL_RULE_LABELS['sensitive_port']} (port {remote_port} from {remote_ip})"
        return effective_severity, rule_label

    # Rule 5: Unsigned/unverified process transmitting while idle
    if not is_process_allowed and not signer and is_idle:
        effective_severity = "CRITICAL"
        rule_label = f"{CRITICAL_RULE_LABELS['unsigned_idle']} ({process_name})"
        return effective_severity, rule_label

    return effective_severity, rule_label


def classify_system_change(
    change: Dict[str, Any],
    known_admin_accounts: Set[str],
    now: Optional[datetime] = None,
) -> Tuple[str, Optional[str]]:
    """Classify a system change event.

    Returns (severity, rule_label).
    """
    if now is None:
        now = datetime.now(timezone.utc)

    item_key = change.get("item_key", "")
    item_path = change.get("item_path", "")
    item_state = change.get("item_state", "")
    category = change.get("category", "")

    # Rule 6a: New admin/privileged user account
    if category == "user_account" and item_key in known_admin_accounts:
        return "CRITICAL", f"{CRITICAL_RULE_LABELS['security_change']} (new admin account: {item_key})"

    # Rule 6b: Firewall disabled or rule removed
    if category == "firewall":
        if "disabled" in (item_state or "").lower() or "removed" in (item_state or "").lower():
            return "CRITICAL", f"{CRITICAL_RULE_LABELS['security_change']} (firewall {item_state})"

    # Rule 6c: Sentinel's own service stopped/tampered
    if category == "service" and "sentinel" in (item_path or item_key).lower():
        if "stopped" in (item_state or "").lower() or "tampered" in (item_state or "").lower():
            return "CRITICAL", f"{CRITICAL_RULE_LABELS['security_change']} (Sentinel service {item_state})"

    # Rule 6d: Security logging disabled
    if category == "security_logging" and "disabled" in (item_state or "").lower():
        return "CRITICAL", f"{CRITICAL_RULE_LABELS['security_change']} (security logging disabled)"

    return "LOG_ONLY", None


class SeverityClassifier:
    """Maintains cross-event state for severity classification."""

    def __init__(self) -> None:
        self.port_scan_tracker: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.known_ips: Set[str] = set()
        self.known_admin_accounts: Set[str] = set()
        self._last_cleanup = datetime.now(timezone.utc).timestamp()

    def cleanup(self, now: Optional[datetime] = None) -> None:
        if now is None:
            now = datetime.now(timezone.utc)
        if now.timestamp() - self._last_cleanup < 60:
            return
        self._last_cleanup = now.timestamp()
        cutoff = now.timestamp() - 120
        for ip in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[ip] = [(ts, p) for ts, p in self.port_scan_tracker[ip] if ts > cutoff]
            if not self.port_scan_tracker[ip]:
                del self.port_scan_tracker[ip]

    def classify_network(
        self,
        alert_type: str,
        process_name: str,
        remote_ip: str,
        remote_port: int,
        is_idle: bool,
        signer: str,
        is_process_allowed: bool,
        severity: str,
    ) -> Tuple[str, Optional[str]]:
        self.cleanup()
        result = classify_network_event(
            alert_type=alert_type,
            process_name=process_name,
            remote_ip=remote_ip or "",
            remote_port=remote_port,
            is_idle=is_idle,
            signer=signer,
            is_process_allowed=is_process_allowed,
            severity=severity,
            port_scan_tracker=self.port_scan_tracker,
            known_ips=self.known_ips,
        )
        if remote_ip:
            self.known_ips.add(remote_ip)
        return result

    def classify_system(self, change: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        return classify_system_change(change, self.known_admin_accounts)
