"""Resource optimizer with protected-service exclusion."""

from __future__ import annotations
import os
import platform
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

PROTECTED_NAMES = {
    "system", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "explorer.exe", "svchost.exe", "kernel_task", "launchd",
    "windowserver", "loginwindow", "systemd", "init", "xorg", "wayland",
}


def is_protected(name: str, pid: int) -> bool:
    lowered = (name or "").lower()
    if lowered in PROTECTED_NAMES:
        return True
    if "sentinel" in lowered:
        return True
    try:
        p = psutil.Process(pid)
        if psutil.Process(1).pid == pid:
            return True
    except Exception:
        pass
    return False


def is_in_use(name: str, pid: int) -> bool:
    try:
        p = psutil.Process(pid)
        try:
            if p.windows():  # type: ignore[attr-defined]
                return True
        except Exception:
            pass
        if p.status() == psutil.STATUS_RUNNING:
            return True
    except Exception:
        pass
    return False


def get_candidates(aggressive: bool = False) -> List[Dict[str, Any]]:
    """Classify running processes as optimization candidates."""
    candidates: List[Dict[str, Any]] = []
    parents: Dict[int, List[psutil.Process]] = {}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "cpu_percent", "memory_info"]):
            try:
                parents.setdefault(proc.info["ppid"], []).append(proc)
            except Exception:
                continue
    except Exception:
        pass

    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                name = info.get("name") or "unknown"
                pid = info.get("pid")
                if is_protected(name, pid):
                    continue
                status = "unknown"
                if is_in_use(name, pid):
                    status = "in_use"
                else:
                    siblings = parents.get(info.get("ppid"), [])
                    same_name = [s for s in siblings if (s.info.get("name") or "").lower() == name.lower()]
                    if len(same_name) > 1:
                        status = "duplicate_helper"
                    else:
                        status = "background_bloat"
                if status == "unknown" and not aggressive:
                    continue
                mem = info.get("memory_info")
                mem_mb = mem.rss / (1024 * 1024) if mem else 0
                candidates.append({
                    "pid": pid,
                    "name": name,
                    "executable_path": info.get("exe") or "",
                    "status": status,
                    "cpu_percent": info.get("cpu_percent") or 0,
                    "memory_mb": round(mem_mb, 1),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass
    return candidates


def optimize_now(aggressive: bool = False) -> Dict[str, Any]:
    """Run the optimizer. Safe tier always runs; aggressive tier only if enabled."""
    results: List[Dict[str, Any]] = []
    for proc in get_candidates(aggressive=aggressive):
        try:
            p = psutil.Process(proc["pid"])
            action = "none"
            if proc["status"] in ("duplicate_helper", "background_bloat"):
                try:
                    if hasattr(p, "nice"):
                        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if platform.system() == "Windows" else 10)
                    action = "lowered_priority"
                except Exception:
                    action = "failed"
            if aggressive and proc["status"] in ("duplicate_helper", "background_bloat"):
                try:
                    p.terminate()
                    action = "terminated"
                except Exception:
                    action = "failed"
            results.append({**proc, "action": action})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "results": results}
