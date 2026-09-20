"""Terminal logger and status formatter for Sentinel."""

from __future__ import annotations
import sys
from datetime import datetime


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def _supports_color() -> bool:
    """Check if color is supported in the current terminal."""
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


_COLOR_ENABLED = _supports_color()


def _format_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def info(msg: str) -> None:
    t = _format_time()
    if _COLOR_ENABLED:
        print(f"{Colors.GRAY}[{t}]{Colors.RESET} {Colors.BLUE}[*]{Colors.RESET} {msg}", flush=True)
    else:
        print(f"[{t}] [*] {msg}", flush=True)


def success(msg: str) -> None:
    t = _format_time()
    if _COLOR_ENABLED:
        print(f"{Colors.GRAY}[{t}]{Colors.RESET} {Colors.GREEN}[+]{Colors.RESET} {msg}", flush=True)
    else:
        print(f"[{t}] [+] {msg}", flush=True)


def warn(msg: str) -> None:
    t = _format_time()
    if _COLOR_ENABLED:
        print(f"{Colors.GRAY}[{t}]{Colors.RESET} {Colors.YELLOW}[!]{Colors.RESET} {msg}", flush=True)
    else:
        print(f"[{t}] [!] {msg}", flush=True)


def alert(msg: str) -> None:
    t = _format_time()
    if _COLOR_ENABLED:
        print(f"{Colors.GRAY}[{t}]{Colors.RESET} {Colors.BOLD}{Colors.RED}[ALERT]{Colors.RESET} {Colors.RED}{msg}{Colors.RESET}", flush=True)
    else:
        print(f"[{t}] [ALERT] {msg}", flush=True)


def debug(msg: str, enabled: bool = False) -> None:
    if not enabled:
        return
    t = _format_time()
    if _COLOR_ENABLED:
        print(f"{Colors.GRAY}[{t}] [DEBUG] {msg}{Colors.RESET}", flush=True)
    else:
        print(f"[{t}] [DEBUG] {msg}", flush=True)
