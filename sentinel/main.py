"""Sentinel - Personal Laptop Security Monitor CLI."""

from __future__ import annotations
import argparse
import signal
import sys
import time
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from sentinel import __version__
from sentinel.config import SentinelConfig
from sentinel.db.storage import Storage
from sentinel.monitor.network import NetworkMonitor
from sentinel.monitor.system_change import SystemChangeDetector
from sentinel.platform_utils.notifier import Notifier
from sentinel.utils import logger
from sentinel.utils.priority import set_low_priority


def _print_banner() -> None:
    print(
        r"""
  ____             _   _            _ 
 / ___|  ___ _ __ | |_(_)_ __   ___| |
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  ___) |  __/ | | | |_| | | | |  __/ |
 |____/ \___|_| |_|\__|_|_| |_|\___|_|  v"""
        + __version__
        + """
 Personal Laptop Security Monitor (Phases 1 & 2 Prototype)
    """
    )


def cmd_run(args: argparse.Namespace) -> None:
    _print_banner()
    config = SentinelConfig.load(args.config)

    if args.poll_interval:
        config.poll_interval_seconds = args.poll_interval
    if args.snapshot_interval:
        config.snapshot_interval_seconds = args.snapshot_interval
    if args.learning_days is not None:
        config.learning_mode_days = args.learning_days
    if args.idle_seconds is not None:
        config.idle_threshold_seconds = args.idle_seconds
    if args.no_notify:
        config.notification_enabled = False

    if config.low_process_priority:
        set_low_priority()

    storage = Storage(config.db_path)
    notifier = Notifier(
        cooldown_seconds=config.notification_cooldown_seconds,
        enabled=config.notification_enabled,
    )

    if args.immediate_mode:
        storage.disable_learning_mode()
        logger.warn("Immediate mode enabled: Learning mode disabled, anomalies will be flagged immediately!")
    else:
        until = storage.init_learning_mode_if_needed(config.learning_mode_days)
        if storage.is_learning_mode_active():
            logger.info(f"Learning Mode ACTIVE until: {until} (no false-alarm alerts during learning)")
        else:
            logger.info("Learning Mode COMPLETE: Baseline allowlist enforced")

    net_monitor = NetworkMonitor(config, storage, notifier)
    sys_detector = SystemChangeDetector(config, storage, notifier)

    logger.info("Checking initial system change snapshot (startup entries, services, scheduled tasks)...")
    sys_res = sys_detector.check_changes(force=True)
    if sys_res.get("new_items", 0) > 0:
        logger.alert(f"Detected {sys_res['new_items']} new system items since previous session!")
    else:
        logger.success("System change baseline synchronized.")

    running = True

    def _sig_handler(signum, frame):
        nonlocal running
        print("\n")
        logger.info("Shutdown signal received. Stopping Sentinel gracefully...")
        running = False

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    logger.success(
        f"Sentinel monitoring started (poll every {config.poll_interval_seconds}s, "
        f"snapshots every {config.snapshot_interval_seconds}s, idle threshold {config.idle_threshold_seconds}s)"
    )
    logger.info("Press Ctrl+C to stop.\n")

    import os
    from datetime import datetime, timezone
    storage.set_meta("daemon_pid", str(os.getpid()))
    storage.set_meta("daemon_started_at", datetime.now(timezone.utc).isoformat())

    try:
        loop_count = 0
        while running:
            loop_count += 1
            try:
                net_res = net_monitor.poll_once()

                sys_detector.check_changes(force=False)

                if loop_count % 12 == 0 or loop_count == 1:
                    mode_str = "LEARNING" if net_res.get("is_learning") else "ALERTING"
                    idle_str = f"idle {int(net_res.get('idle_seconds', 0))}s"
                    if net_res.get("flagged", 0) > 0:
                        logger.alert(
                            f"Cycle #{loop_count}: {net_res['flagged']} FLAGGED connections! "
                            f"(Total active: {net_res['total_connections']}) [{mode_str} mode | {idle_str}]"
                        )
                    else:
                        logger.info(
                            f"Cycle #{loop_count}: {net_res['total_connections']} connections active "
                            f"[{mode_str} mode | {idle_str}]"
                        )

            except Exception as e:
                logger.warn(f"Error in monitoring loop: {e}")

            sleep_until = time.time() + config.poll_interval_seconds
            while running and time.time() < sleep_until:
                time.sleep(0.2)
    finally:
        storage.set_meta("daemon_pid", "")
        logger.success("Sentinel monitor stopped. Database state saved.")


def cmd_status(args: argparse.Namespace) -> None:
    import os
    import psutil
    from sentinel.platform_utils import autostart

    config = SentinelConfig.load(args.config)
    storage = Storage(config.db_path)
    stats = storage.get_stats()

    daemon_pid_str = storage.get_meta("daemon_pid")
    is_running = False
    proc_info = "STOPPED (Not running)"

    if daemon_pid_str and daemon_pid_str.isdigit():
        pid = int(daemon_pid_str)
        if psutil.pid_exists(pid):
            try:
                p = psutil.Process(pid)
                mem_mb = p.memory_info().rss / (1024 * 1024)
                proc_info = f"ACTIVE in background (PID: {pid}, Process: {p.name()}, Memory: {mem_mb:.1f} MB)"
                is_running = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    if not is_running:
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if p.info["pid"] == os.getpid():
                    continue
                cmd = " ".join(p.info.get("cmdline") or [])
                if ("main.py" in cmd or "sentinel" in cmd) and "run" in cmd:
                    mem_mb = p.memory_info().rss / (1024 * 1024)
                    proc_info = f"ACTIVE in background (PID: {p.info['pid']}, Process: {p.info['name']}, Memory: {mem_mb:.1f} MB)"
                    is_running = True
                    break
            except Exception:
                pass

    autostart_active = autostart.is_autostart_enabled()
    autostart_str = "ENABLED (Starts automatically on laptop boot/login)" if autostart_active else "DISABLED"

    print("\n--- Sentinel System Status ---")
    print(f"Background Daemon   : {proc_info}")
    print(f"Autostart on Boot   : {autostart_str}")
    print(f"Database Path       : {stats['db_path']}")
    print(f"Learning Mode Active: {'YES (Collecting baseline)' if stats['is_learning_mode_active'] else 'NO (Security Alerts Active)'}")
    print(f"Learning Mode Until : {stats['learning_mode_until']}")
    print(f"Allowlist Entries   : {stats['allowlist_entries']} trusted processes")
    print(f"Network Events Log  : {stats['network_events_total']} (flagged: {stats['network_events_flagged']})")
    print(f"System Snapshots    : {stats['system_snapshots_recorded']} records")
    print(f"Total Alerts Fired  : {stats['alerts_total']}")
    print("------------------------------\n")


def cmd_stop(args: argparse.Namespace) -> None:
    import os
    import psutil
    config = SentinelConfig.load(args.config)
    storage = Storage(config.db_path)
    killed = False

    daemon_pid_str = storage.get_meta("daemon_pid")
    if daemon_pid_str and daemon_pid_str.isdigit():
        pid = int(daemon_pid_str)
        if psutil.pid_exists(pid):
            try:
                p = psutil.Process(pid)
                p.terminate()
                killed = True
                logger.success(f"Stopped background Sentinel process (PID: {pid}).")
            except Exception as e:
                logger.warn(f"Failed to terminate PID {pid}: {e}")

    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.info["pid"] == os.getpid():
                continue
            cmd = " ".join(p.info.get("cmdline") or [])
            if ("main.py" in cmd or "sentinel" in cmd) and "run" in cmd:
                p.terminate()
                killed = True
                logger.success(f"Stopped background Sentinel process ({p.info['name']}, PID: {p.info['pid']}).")
        except Exception:
            pass

    storage.set_meta("daemon_pid", "")
    if not killed:
        logger.info("No active Sentinel background process was found.")


def cmd_allowlist(args: argparse.Namespace) -> None:
    config = SentinelConfig.load(args.config)
    storage = Storage(config.db_path)

    if args.action == "list":
        entries = storage.get_allowlist()
        print(f"\n--- Baseline Allowlist ({len(entries)} processes) ---")
        print(f"{'Process Name':<32} {'Path':<40} {'Signer':<25} {'Seen':<8} {'Manual':<8} {'Last Seen'}")
        print("-" * 150)
        for e in entries:
            manual_str = "YES" if e.get("is_manual") else "Auto"
            path = (e.get("executable_path", "") or "")[:39]
            signer = (e.get("signer", "") or "")[:24]
            print(f"{e['process_name']:<32} {path:<40} {signer:<25} {e.get('connection_count', 1):<8} {manual_str:<8} {e.get('last_seen', '')[:19]}")
        print("-" * 150)
        print()

    elif args.action == "add":
        if not args.process:
            print("Error: Specify process name to add, e.g.: sentinel allowlist add chrome.exe")
            sys.exit(1)
        storage.add_allowlist_entry(args.process, manual=True)
        logger.success(f"Added '{args.process}' to allowlist.")

    elif args.action == "remove":
        if not args.process:
            print("Error: Specify process name to remove, e.g.: sentinel allowlist remove badapp.exe")
            sys.exit(1)
        if storage.remove_allowlist_entry(args.process):
            logger.success(f"Removed '{args.process}' from allowlist.")
        else:
            logger.warn(f"'{args.process}' was not found in allowlist.")

    elif args.action == "trust-signer":
        if not args.signer:
            print("Error: Specify signer name, e.g.: sentinel allowlist trust-signer \"Microsoft Corporation\"")
            sys.exit(1)
        storage.add_trusted_signer(args.signer, manual=True)
        logger.success(f"Trusted signer '{args.signer}' added — any process signed by this entity is now globally trusted.")

    elif args.action == "list-trusted":
        signers = storage.get_trusted_signers()
        if not signers:
            print("\nNo globally trusted signers.\n")
        else:
            print(f"\n--- Globally Trusted Signers ({len(signers)}) ---")
            for s in signers:
                manual_str = "YES" if s.get("is_manual") else "Auto"
                print(f"  {s['signer']}  (added: {s.get('first_seen', '')[:19]}, manual: {manual_str})")
            print()

    elif args.action == "grouped":
        entries = storage.get_grouped_alerts()
        if not entries:
            print("\nNo grouped alerts.\n")
        else:
            print(f"\n--- Grouped Alerts ({len(entries)}) ---")
            print(f"{'Process':<32} {'Type':<28} {'Severity':<10} {'Count':<8} {'First Seen':<20} {'Last Seen':<20}")
            print("-" * 130)
            for e in entries:
                snoozed = " [SNOOZED]" if (e.get("snoozed_until") or "") else ""
                print(f"{e.get('process_name', ''):<32} {e.get('alert_type', ''):<28} {e.get('severity', ''):<10} {e.get('occurrence_count', 1):<8} {e.get('first_seen', '')[:19]:<20} {e.get('last_seen', '')[:19]:<20}{snoozed}")
            print("-" * 130)
            print()

    elif args.action == "snooze":
        if not args.identity:
            print("Error: Specify alert identity key to snooze, e.g.: sentinel allowlist snooze OneDrive.exe|network_trusted_unrecognized|20.135.6.11")
            sys.exit(1)
        duration = args.duration or "1hr"
        storage.snooze_alert(args.identity, duration=duration)
        logger.success(f"Snoozed alert '{args.identity}' for {duration}.")

    elif args.action == "unsnooze":
        if not args.identity:
            print("Error: Specify alert identity key to unsnooze.")
            sys.exit(1)
        storage.unsnooze_alert(args.identity)
        logger.success(f"Unsnoozed alert '{args.identity}'.")

    elif args.action == "snoozed":
        entries = storage.get_snoozed_alerts()
        if not entries:
            print("\nNo snoozed alerts.\n")
        else:
            print(f"\n--- Snoozed Alerts ({len(entries)}) ---")
            for e in entries:
                print(f"  {e['identity_key']}  (until: {(e.get('snoozed_until') or '')[:19]}, occurrences: {e.get('occurrence_count', 1)})")
            print()

    elif args.action == "severity-override":
        if not args.alert_type or not args.severity:
            print("Error: Specify alert_type and severity, e.g.: sentinel allowlist severity-override network_trusted_unrecognized critical")
            sys.exit(1)
        storage.add_severity_override(args.alert_type, args.severity, reason="user override")
        logger.success(f"Severity override set: '{args.alert_type}' -> {args.severity}")

    elif args.action == "remove-severity-override":
        if not args.alert_type:
            print("Error: Specify alert_type to remove override.")
            sys.exit(1)
        if storage.remove_severity_override(args.alert_type):
            logger.success(f"Removed severity override for '{args.alert_type}'.")
        else:
            logger.warn(f"No override found for '{args.alert_type}'.")

    elif args.action == "block":
        if not args.target_type or not args.target_value:
            print("Error: Specify target_type and target_value, e.g.: sentinel allowlist block process bad.exe")
            sys.exit(1)
        storage.add_blocklist_entry(args.target_type, args.target_value, reason="user blocked")
        logger.success(f"Blocked {args.target_type} '{args.target_value}'.")

    elif args.action == "unblock":
        if not args.target_type or not args.target_value:
            print("Error: Specify target_type and target_value to unblock.")
            sys.exit(1)
        if storage.remove_blocklist_entry(args.target_type, args.target_value):
            logger.success(f"Unblocked {args.target_type} '{args.target_value}'.")
        else:
            logger.warn(f"'{args.target_value}' was not found in blocklist.")

    elif args.action == "blocklist":
        entries = storage.get_blocklist()
        if not entries:
            print("\nBlocklist is empty.\n")
        else:
            print(f"\n--- Blocklist ({len(entries)}) ---")
            for e in entries:
                print(f"  {e['target_type']}: {e['target_value']}  (reason: {e.get('reason', '')})")
            print()


def cmd_alerts(args: argparse.Namespace) -> None:
    config = SentinelConfig.load(args.config)
    storage = Storage(config.db_path)
    alerts = storage.get_recent_alerts(limit=args.limit)

    severity_filter = getattr(args, "severity", None)
    if severity_filter == "critical":
        alerts = [a for a in alerts if a.get("severity") == "critical"]
    elif severity_filter == "log_only":
        alerts = [a for a in alerts if a.get("severity") == "log_only"]

    print(f"\n--- Recent Security Alerts ({len(alerts)}) ---")
    if not alerts:
        print("No alerts recorded yet.")
    for a in alerts:
        sev = a["severity"].upper()
        print(f"[{a['timestamp'][:19]}] [{sev}] {a['alert_type']}: {a['message']}")
    print("---------------------------------------------------\n")


def cmd_snapshot(args: argparse.Namespace) -> None:
    config = SentinelConfig.load(args.config)
    storage = Storage(config.db_path)
    notifier = Notifier(enabled=False)
    detector = SystemChangeDetector(config, storage, notifier)

    logger.info("Executing on-demand system change snapshot inspection...")
    res = detector.check_changes(force=True)
    print("\n--- System Snapshot Inspection ---")
    for cat, data in res.get("details", {}).items():
        base = data.get("baseline_count")
        new_cnt = len(data.get("new", []))
        mod_cnt = len(data.get("modified", []))
        if base is not None:
            print(f"{cat:<16}: Initial baseline established ({base} items)")
        else:
            print(f"{cat:<16}: {new_cnt} new items, {mod_cnt} modified items")
    print("----------------------------------\n")


def cmd_test_notify(args: argparse.Namespace) -> None:
    notifier = Notifier(enabled=True)
    logger.info("Sending test desktop notification...")
    sent = notifier.notify(
        title="Sentinel Security Monitor",
        message="This is a test notification from Sentinel. Alerts are functioning correctly!",
        severity="medium",
    )
    if sent:
        logger.success("Test notification dispatched.")
    else:
        logger.warn("Test notification could not be dispatched.")


def cmd_autostart(args: argparse.Namespace) -> None:
    from sentinel.platform_utils import autostart
    if args.action == "enable":
        autostart.enable_autostart()
    elif args.action == "disable":
        autostart.disable_autostart()
    elif args.action == "status":
        enabled = autostart.is_autostart_enabled()
        status_str = "ENABLED (Runs automatically in background on boot/login)" if enabled else "DISABLED (Manual launch only)"
        print(f"\nSentinel Background Autostart: {status_str}\n")


def cmd_dashboard(args: argparse.Namespace) -> None:
    import threading
    from sentinel.dashboard.app import create_app
    app = create_app()
    logger.success(f"Dashboard running at http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, use_reloader=False)


def cmd_optimize(args: argparse.Namespace) -> None:
    from sentinel.platform_utils.optimizer import optimize_now
    result = optimize_now(aggressive=False)
    print(f"\nOptimized at {result['timestamp']}")
    for r in result["results"]:
        print(f"  {r['name']} (PID {r['pid']}): {r['action']}")


def cmd_optimize_now(args: argparse.Namespace) -> None:
    from sentinel.platform_utils.optimizer import optimize_now
    result = optimize_now(aggressive=args.aggressive)
    print(f"\nOptimized at {result['timestamp']}")
    for r in result["results"]:
        print(f"  {r['name']} (PID {r['pid']}): {r['action']}")


def cmd_overlay(args: argparse.Namespace) -> None:
    from sentinel.platform_utils.overlay import run_overlay
    run_overlay()


def cmd_control_panel(args: argparse.Namespace) -> None:
    from sentinel.platform_utils.control_panel import run_control_panel
    run_control_panel()


def _hide_console() -> None:
    """Best-effort hide of any attached console window on Windows."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel - Personal Laptop Security Monitor (Phases 1 & 2 Prototype)",
    )
    parser.add_argument("--config", "-c", help="Path to sentinel_config.json")
    parser.add_argument("--hidden", action="store_true", help="Run completely hidden with no console window (Windows only)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    run_parser = subparsers.add_parser("run", help="Start continuous monitoring daemon")
    run_parser.add_argument("--poll-interval", type=float, help="Seconds between network connection polls (default: 5.0)")
    run_parser.add_argument("--snapshot-interval", type=float, help="Seconds between system snapshots (default: 300.0)")
    run_parser.add_argument("--learning-days", type=float, help="Days to run in learning mode (default: 7.0)")
    run_parser.add_argument("--idle-seconds", type=float, help="Idle threshold seconds (default: 300.0)")
    run_parser.add_argument("--immediate-mode", action="store_true", help="Bypass learning mode for immediate anomaly alerting")
    run_parser.add_argument("--no-notify", action="store_true", help="Disable desktop popups (console/log only)")

    subparsers.add_parser("status", help="Show database metrics and monitoring state")

    al_parser = subparsers.add_parser("allowlist", help="Manage allowed processes")
    al_parser.add_argument("action", choices=["list", "add", "remove", "trust-signer", "list-trusted", "grouped", "snooze", "unsnooze", "snoozed", "severity-override", "remove-severity-override", "block", "unblock", "blocklist"], help="Allowlist action")
    al_parser.add_argument("process", nargs="?", help="Process name (for add/remove)")
    al_parser.add_argument("--signer", help="Signer name (for trust-signer action)")
    al_parser.add_argument("--identity", help="Alert identity key (for snooze/unsnooze)")
    al_parser.add_argument("--duration", choices=["1hr", "24hr", "forever"], default="1hr", help="Snooze duration (default: 1hr)")
    al_parser.add_argument("--alert-type", help="Alert type (for severity-override)")
    al_parser.add_argument("--severity", help="Severity value (for severity-override)")
    al_parser.add_argument("--target-type", help="Target type (for block/unblock)")
    al_parser.add_argument("--target-value", help="Target value (for block/unblock)")

    alerts_parser = subparsers.add_parser("alerts", help="View recent security alerts")
    alerts_parser.add_argument("--limit", type=int, default=30, help="Number of alerts to show (default: 30)")
    alerts_parser.add_argument("--severity", choices=["critical", "log_only"], help="Filter by severity")

    subparsers.add_parser("snapshot", help="Run an immediate system change snapshot check")

    subparsers.add_parser("test-notify", help="Send a test desktop notification")

    auto_parser = subparsers.add_parser("autostart", help="Configure background autostart on laptop boot/login")
    auto_parser.add_argument("action", choices=["enable", "disable", "status"], help="Autostart action")

    dashboard_parser = subparsers.add_parser("dashboard", help="Open local review dashboard")
    dashboard_parser.add_argument("--port", type=int, default=5000, help="Port for dashboard server (default: 5000)")

    subparsers.add_parser("optimize", help="Run resource optimizer (safe tier)")

    optimize_parser = subparsers.add_parser("optimize-now", help="Run resource optimizer")
    optimize_parser.add_argument("--aggressive", action="store_true", help="Enable aggressive tier (terminate processes)")

    subparsers.add_parser("overlay", help="Start always-on-top alert overlay")

    subparsers.add_parser("control-panel", help="Open desktop control panel GUI")

    args = parser.parse_args()

    if getattr(args, "hidden", False):
        _hide_console()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "run": cmd_run,
        "status": cmd_status,
        "allowlist": cmd_allowlist,
        "alerts": cmd_alerts,
        "snapshot": cmd_snapshot,
        "test-notify": cmd_test_notify,
        "autostart": cmd_autostart,
        "dashboard": cmd_dashboard,
        "optimize": cmd_optimize,
        "optimize-now": cmd_optimize_now,
        "overlay": cmd_overlay,
        "control-panel": cmd_control_panel,
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(args)


if __name__ == "__main__":
    main()
