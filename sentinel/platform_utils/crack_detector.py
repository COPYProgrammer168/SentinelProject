"""Heuristic crack/unauthorized software detection."""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

CRACK_PATTERNS = ["crack", "keygen", "patch", "activator", "loader"]
DOWNLOADS_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
]
TORRENT_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads", "uTorrent"),
    os.path.join(os.path.expanduser("~"), "Downloads", "BitTorrent"),
    os.path.join(os.path.expanduser("~"), "Downloads", "qBittorrent"),
    os.path.join(os.path.expanduser("~"), "Downloads", "Transmission"),
    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
]


def is_potentially_cracked(name: str, exe_path: str, signer: str) -> bool:
    """Return True if the executable matches crack/unauthorized heuristics."""
    if signer:
        return False
    base = os.path.basename(exe_path or name)
    lowered = base.lower()
    if any(p in lowered for p in CRACK_PATTERNS):
        return True
    for d in DOWNLOADS_DIRS + TORRENT_DIRS:
        try:
            if Path(exe_path or name).resolve().is_relative_to(Path(d).resolve()):
                return True
        except (ValueError, OSError):
            pass
    return False


def check_process(pid: int, name: str, exe_path: str, signer: str) -> Optional[Dict[str, str]]:
    """Check a single process for crack/unauthorized indicators.

    Returns a dict with details if flagged, or None if clean.
    """
    if is_potentially_cracked(name, exe_path, signer):
        return {
            "pid": str(pid),
            "process_name": name,
            "executable_path": exe_path,
            "signer": signer,
            "reason": "heuristic_match",
        }
    return None
