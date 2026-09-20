"""Cross-platform user idle detection."""

from __future__ import annotations
import os
import shutil
import subprocess
import sys
from sentinel.utils import logger


def get_idle_seconds() -> float:
    """Return how many seconds have elapsed since the user last provided keyboard or mouse input.
    Returns 0.0 if unable to determine or if user was recently active.
    """
    if sys.platform == "win32":
        return _get_idle_windows()
    elif sys.platform == "darwin":
        return _get_idle_macos()
    else:
        return _get_idle_linux()


def _get_idle_windows() -> float:
    try:
        import ctypes

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            return 0.0

        # Try GetTickCount64 first to avoid 49.7 day wrap-around; fallback to GetTickCount
        if hasattr(ctypes.windll.kernel32, "GetTickCount64"):
            ticks = ctypes.windll.kernel32.GetTickCount64()
            # dwTime is 32-bit, so compare with lower 32 bits if needed
            ticks_32 = ticks & 0xFFFFFFFF
            millis = (ticks_32 - lii.dwTime) & 0xFFFFFFFF
        else:
            ticks = ctypes.windll.kernel32.GetTickCount()
            millis = (ticks - lii.dwTime) & 0xFFFFFFFF

        return max(0.0, millis / 1000.0)
    except Exception as e:
        logger.debug(f"Windows idle check failed: {e}")
        return 0.0


def _get_idle_macos() -> float:
    try:
        # ioreg command outputs HIDIdleTime in nanoseconds
        cmd = ["ioreg", "-c", "IOHIDSystem"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
        for line in proc.stdout.splitlines():
            if "HIDIdleTime" in line:
                parts = line.split("=")
                if len(parts) >= 2:
                    nanos = int(parts[1].strip())
                    return max(0.0, nanos / 1_000_000_000.0)
    except Exception as e:
        logger.debug(f"macOS idle check failed: {e}")
    return 0.0


def _get_idle_linux() -> float:
    # 1. Try xprintidle (returns idle time in milliseconds)
    if shutil.which("xprintidle"):
        try:
            res = subprocess.run(["xprintidle"], capture_output=True, text=True, timeout=2.0)
            if res.returncode == 0 and res.stdout.strip().isdigit():
                return max(0.0, float(res.stdout.strip()) / 1000.0)
        except Exception:
            pass

    # 2. Try inspecting mtime of /dev/input/event* (requires read access)
    try:
        import time
        input_dir = "/dev/input"
        if os.path.exists(input_dir):
            latest_mtime = 0.0
            for entry in os.scandir(input_dir):
                if entry.name.startswith("event"):
                    st = entry.stat()
                    if st.st_mtime > latest_mtime:
                        latest_mtime = st.st_mtime
            if latest_mtime > 0:
                return max(0.0, time.time() - latest_mtime)
    except Exception:
        pass

    return 0.0
