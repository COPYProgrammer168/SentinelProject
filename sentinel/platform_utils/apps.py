"""Application discovery for the dashboard Applications panel.

Enumerates currently running processes and installed applications,
merges them by identity, and returns a unified list.
"""

from __future__ import annotations
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def get_running_apps() -> List[Dict[str, Any]]:
    """Get currently running processes grouped by application name."""
    try:
        import psutil
    except ImportError:
        return []

    apps: Dict[str, Dict[str, Any]] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            info = proc.info
            name = info.get("name") or "unknown"
            exe = info.get("exe") or ""
            key = name.lower()
            if key not in apps:
                apps[key] = {
                    "name": name,
                    "executable_path": exe,
                    "status": "Running",
                    "pids": [info.get("pid")],
                    "last_seen": info.get("create_time"),
                }
            else:
                apps[key]["pids"].append(info.get("pid"))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return list(apps.values())


def get_installed_apps() -> List[Dict[str, Any]]:
    """Get installed but not-running applications."""
    system = platform.system()
    if system == "Windows":
        return _get_installed_windows()
    elif system == "Darwin":
        return _get_installed_macos()
    else:
        return _get_installed_linux()


def _get_installed_windows() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        import winreg
    except ImportError:
        return items
    registry_targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, subkey in registry_targets:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[0]
                for i in range(count):
                    try:
                        with winreg.OpenKey(hive, f"{subkey}\\{winreg.EnumKey(key, i)}", 0, winreg.KEY_READ) as sub:
                            name = ""
                            try:
                                name = winreg.QueryValueEx(sub, "DisplayName")[0]
                            except OSError:
                                continue
                            if not name:
                                continue
                            path = ""
                            try:
                                path = (winreg.QueryValueEx(sub, "InstallLocation")[0] if winreg.QueryValueEx(sub, "InstallLocation") else "")
                            except OSError:
                                pass
                            items.append({
                                "name": name,
                                "executable_path": path or "",
                                "status": "Installed",
                                "pids": [],
                                "last_seen": None,
                            })
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass
    return items


def _get_installed_macos() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    app_dir = Path("/Applications")
    if not app_dir.is_dir():
        return items
    for entry in app_dir.iterdir():
        if entry.suffix == ".app":
            items.append({
                "name": entry.name.replace(".app", ""),
                "executable_path": str(entry),
                "status": "Installed",
                "pids": [],
                "last_seen": None,
            })
    return items


def _get_installed_linux() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    desktop_dirs = [
        Path("/usr/share/applications"),
        Path.home() / ".local/share/applications",
    ]
    for directory in desktop_dirs:
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if entry.suffix == ".desktop":
                try:
                    with open(entry, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.startswith("Name="):
                                name = line.split("=", 1)[1].strip()
                                items.append({
                                    "name": name,
                                    "executable_path": str(entry),
                                    "status": "Installed",
                                    "pids": [],
                                    "last_seen": None,
                                })
                                break
                except Exception:
                    continue
    return items


def get_all_apps() -> List[Dict[str, Any]]:
    """Merge running and installed apps, deduplicated by name + path."""
    running = {a["name"].lower(): a for a in get_running_apps()}
    installed = {a["name"].lower(): a for a in get_installed_apps()}
    merged: Dict[str, Dict[str, Any]] = {}
    for key, app in {**running, **installed}.items():
        app["trusted"] = False
        app["protected"] = _is_protected(app)
        merged[key] = app
    return list(merged.values())


def _is_protected(app: Dict[str, Any]) -> bool:
    name = (app.get("name") or "").lower()
    path = (app.get("executable_path") or "").lower()
    critical_windows = {"system", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "explorer.exe", "svchost.exe"}
    critical_macos = {"kernel_task", "launchd", "windowserver", "loginwindow"}
    critical_linux = {"systemd", "init", "xorg", "wayland"}
    system = platform.system()
    if system == "Windows" and name in critical_windows:
        return True
    if system == "Darwin" and name in critical_macos:
        return True
    if system == "Linux" and name in critical_linux:
        return True
    if "sentinel" in name:
        return True
    return False
