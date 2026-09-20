"""Cross-platform snapshot collectors for autostart entries, services, and scheduled tasks."""

from __future__ import annotations
import csv
import hashlib
import io
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
import psutil
from sentinel.utils import logger


def _hash_str(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()[:16]


def collect_startup_items() -> List[Dict[str, Any]]:
    """Collect autostart/startup persistence entries."""
    if sys.platform == "win32":
        return _collect_startup_windows()
    elif sys.platform == "darwin":
        return _collect_startup_macos()
    else:
        return _collect_startup_linux()


def collect_services() -> List[Dict[str, Any]]:
    """Collect system services and their running status."""
    if sys.platform == "win32":
        return _collect_services_windows()
    elif sys.platform == "darwin":
        return _collect_services_macos()
    else:
        return _collect_services_linux()


def collect_scheduled_tasks() -> List[Dict[str, Any]]:
    """Collect scheduled tasks / cron jobs / timers."""
    if sys.platform == "win32":
        return _collect_scheduled_tasks_windows()
    elif sys.platform == "darwin":
        return _collect_scheduled_tasks_macos()
    else:
        return _collect_scheduled_tasks_linux()


# =====================================================================
# Windows Implementation
# =====================================================================

def _collect_startup_windows() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    import winreg

    # 1. Registry Run & RunOnce keys
    registry_targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU:RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM:RunOnce"),
    ]

    for hive, subkey, prefix in registry_targets:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        item_key = f"{prefix}\\{val_name}"
                        item_path = str(val_data)
                        items.append({
                            "item_key": item_key,
                            "item_path": item_path,
                            "item_state": "enabled",
                            "hash": _hash_str(f"{item_key}|{item_path}"),
                        })
                    except OSError:
                        continue
        except OSError:
            pass

    # 2. Windows Startup Folders
    user_startup = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    common_startup = os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup")

    for folder, prefix in [(user_startup, "UserStartup"), (common_startup, "CommonStartup")]:
        p = Path(folder)
        if p.is_dir():
            try:
                for entry in p.iterdir():
                    if entry.name.lower() in ("desktop.ini",):
                        continue
                    item_key = f"{prefix}\\{entry.name}"
                    items.append({
                        "item_key": item_key,
                        "item_path": str(entry.resolve()),
                        "item_state": "present",
                        "hash": _hash_str(f"{item_key}|{entry.stat().st_mtime}"),
                    })
            except Exception as e:
                logger.debug(f"Error reading startup folder {folder}: {e}")

    return items


def _collect_services_windows() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        for s in psutil.win_service_iter():
            try:
                info = s.as_dict()
                name = info.get("name") or "unknown"
                display_name = info.get("display_name") or ""
                binpath = info.get("binpath") or ""
                status = info.get("status") or "unknown"
                start_type = info.get("start_type") or "unknown"

                item_key = f"Service:{name}"
                item_path = binpath
                item_state = f"{status}|{start_type}"
                items.append({
                    "item_key": item_key,
                    "item_path": item_path,
                    "item_state": item_state,
                    "hash": _hash_str(f"{item_key}|{item_path}|{display_name}"),
                })
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"Error enumerating Windows services: {e}")
    return items


def _collect_scheduled_tasks_windows() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        res = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=10.0,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode == 0 and res.stdout:
            reader = csv.reader(io.StringIO(res.stdout))
            for row in reader:
                if not row or len(row) < 2:
                    continue
                task_name = row[0].strip()
                if not task_name:
                    continue
                status = row[2].strip() if len(row) > 2 else (row[1].strip() if len(row) > 1 else "Unknown")
                item_key = f"Task:{task_name}"
                items.append({
                    "item_key": item_key,
                    "item_path": task_name,
                    "item_state": status,
                    "hash": _hash_str(f"{item_key}|{status}"),
                })
    except Exception as e:
        logger.debug(f"Error querying Windows scheduled tasks: {e}")
    return items


# =====================================================================
# macOS Implementation
# =====================================================================

def _collect_startup_macos() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    paths = [
        (Path.home() / "Library" / "LaunchAgents", "UserLaunchAgent"),
        (Path("/Library/LaunchAgents"), "GlobalLaunchAgent"),
        (Path("/Library/LaunchDaemons"), "SystemLaunchDaemon"),
    ]
    for directory, prefix in paths:
        if directory.is_dir():
            try:
                for entry in directory.iterdir():
                    if entry.suffix == ".plist":
                        item_key = f"{prefix}:{entry.name}"
                        items.append({
                            "item_key": item_key,
                            "item_path": str(entry),
                            "item_state": "present",
                            "hash": _hash_str(f"{item_key}|{entry.stat().st_mtime}"),
                        })
            except Exception:
                pass
    return items


def _collect_services_macos() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        res = subprocess.run(["launchctl", "list"], capture_output=True, text=True, timeout=5.0)
        if res.returncode == 0:
            for line in res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    label = parts[2]
                    status = parts[1]
                    item_key = f"Launchd:{label}"
                    items.append({
                        "item_key": item_key,
                        "item_path": label,
                        "item_state": f"exit:{status}",
                        "hash": _hash_str(f"{item_key}|{status}"),
                    })
    except Exception:
        pass
    return items


def _collect_scheduled_tasks_macos() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        res = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3.0)
        if res.returncode == 0:
            for i, line in enumerate(res.stdout.splitlines()):
                line = line.strip()
                if line and not line.startswith("#"):
                    item_key = f"Crontab:User:{i}"
                    items.append({
                        "item_key": item_key,
                        "item_path": line,
                        "item_state": "active",
                        "hash": _hash_str(f"{item_key}|{line}"),
                    })
    except Exception:
        pass
    return items


# =====================================================================
# Linux Implementation
# =====================================================================

def _collect_startup_linux() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    paths = [
        (Path.home() / ".config" / "autostart", "UserAutostart"),
        (Path("/etc/xdg/autostart"), "SystemAutostart"),
    ]
    for directory, prefix in paths:
        if directory.is_dir():
            try:
                for entry in directory.iterdir():
                    if entry.suffix == ".desktop":
                        item_key = f"{prefix}:{entry.name}"
                        items.append({
                            "item_key": item_key,
                            "item_path": str(entry),
                            "item_state": "present",
                            "hash": _hash_str(f"{item_key}|{entry.stat().st_mtime}"),
                        })
            except Exception:
                pass
    return items


def _collect_services_linux() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if shutil.which("systemctl"):
        try:
            res = subprocess.run(
                ["systemctl", "list-unit-files", "--type=service", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        unit = parts[0]
                        state = parts[1]
                        item_key = f"SystemdService:{unit}"
                        items.append({
                            "item_key": item_key,
                            "item_path": unit,
                            "item_state": state,
                            "hash": _hash_str(f"{item_key}|{state}"),
                        })
        except Exception:
            pass
    return items


def _collect_scheduled_tasks_linux() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    # Crontabs
    try:
        res = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3.0)
        if res.returncode == 0:
            for i, line in enumerate(res.stdout.splitlines()):
                line = line.strip()
                if line and not line.startswith("#"):
                    item_key = f"Crontab:User:{i}"
                    items.append({
                        "item_key": item_key,
                        "item_path": line,
                        "item_state": "active",
                        "hash": _hash_str(f"{item_key}|{line}"),
                    })
    except Exception:
        pass

    # Systemd timers
    if shutil.which("systemctl"):
        try:
            res = subprocess.run(
                ["systemctl", "list-timers", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if parts:
                        unit = parts[-1]
                        item_key = f"SystemdTimer:{unit}"
                        items.append({
                            "item_key": item_key,
                            "item_path": unit,
                            "item_state": "active",
                            "hash": _hash_str(f"{item_key}|{unit}"),
                        })
        except Exception:
            pass
    return items
