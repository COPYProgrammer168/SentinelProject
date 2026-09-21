"""Cross-platform background autostart configuration for Sentinel."""

from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path
from sentinel.utils import logger


def _get_pythonw_path() -> str:
    """Find pythonw.exe on Windows for windowless background execution."""
    # 1. Check same folder as sys.executable
    curr_dir = Path(sys.executable).parent
    pythonw = curr_dir / "pythonw.exe"
    if pythonw.is_file():
        return str(pythonw)

    # 2. Check virtualenv's Scripts/pythonw.exe
    venv_pythonw = Path(__file__).resolve().parent.parent.parent / ".venv" / "Scripts" / "pythonw.exe"
    if venv_pythonw.is_file():
        return str(venv_pythonw)

    # 3. Fallback to which
    w = shutil.which("pythonw")
    if w:
        return w

    return sys.executable


def _get_main_py_path() -> str:
    return str(Path(__file__).resolve().parent.parent.parent / "main.py")


def enable_autostart() -> bool:
    """Register Sentinel to launch automatically on user login/boot."""
    if sys.platform == "win32":
        return _enable_windows()
    elif sys.platform == "darwin":
        return _enable_macos()
    else:
        return _enable_linux()


def disable_autostart() -> bool:
    """Unregister Sentinel autostart."""
    if sys.platform == "win32":
        return _disable_windows()
    elif sys.platform == "darwin":
        return _disable_macos()
    else:
        return _disable_linux()


def is_autostart_enabled() -> bool:
    """Check if autostart entry exists."""
    if sys.platform == "win32":
        return _is_enabled_windows()
    elif sys.platform == "darwin":
        return _is_enabled_macos()
    else:
        return _is_enabled_linux()


# ---------------- Windows Implementation ----------------

def _get_windows_startup_vbs() -> Path:
    startup_dir = Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"))
    return startup_dir / "SentinelMonitor.vbs"


def _enable_windows() -> bool:
    try:
        vbs_path = _get_windows_startup_vbs()
        vbs_path.parent.mkdir(parents=True, exist_ok=True)

        pythonw = _get_pythonw_path()
        main_py = _get_main_py_path()

        vbs_content = (
            f'CreateObject("Wscript.Shell").Run '
            f'""{pythonw}"" --hidden -m sentinel.main run", 0, False\n'
        )

        with open(vbs_path, "w", encoding="utf-8") as f:
            f.write(vbs_content)

        logger.success(f"Autostart enabled! Launcher installed to: {vbs_path}")
        logger.info(f"Using windowless Python: {pythonw}")
        return True
    except Exception as e:
        logger.warn(f"Failed to enable Windows autostart: {e}")
        return False


def _disable_windows() -> bool:
    try:
        vbs_path = _get_windows_startup_vbs()
        if vbs_path.is_file():
            vbs_path.unlink()
            logger.success("Autostart disabled. Launcher removed from Startup folder.")
            return True
        else:
            logger.info("Autostart is not currently enabled.")
            return True
    except Exception as e:
        logger.warn(f"Failed to disable Windows autostart: {e}")
        return False


def _is_enabled_windows() -> bool:
    return _get_windows_startup_vbs().is_file()


# ---------------- macOS Implementation ----------------

def _get_macos_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / "com.sentinel.securitymonitor.plist"


def _enable_macos() -> bool:
    try:
        plist_path = _get_macos_plist_path()
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        python_exe = sys.executable
        main_py = _get_main_py_path()

        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel.securitymonitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>
        <string>{main_py}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        with open(plist_path, "w", encoding="utf-8") as f:
            f.write(plist_content)
        logger.success(f"macOS LaunchAgent created at {plist_path}")
        return True
    except Exception as e:
        logger.warn(f"Failed to enable macOS autostart: {e}")
        return False


def _disable_macos() -> bool:
    try:
        plist_path = _get_macos_plist_path()
        if plist_path.is_file():
            plist_path.unlink()
            logger.success("macOS LaunchAgent removed.")
            return True
        return True
    except Exception as e:
        logger.warn(f"Failed to disable macOS autostart: {e}")
        return False


def _is_enabled_macos() -> bool:
    return _get_macos_plist_path().is_file()


# ---------------- Linux Implementation ----------------

def _get_linux_service_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / "sentinel.service"


def _enable_linux() -> bool:
    try:
        service_path = _get_linux_service_path()
        service_path.parent.mkdir(parents=True, exist_ok=True)
        python_exe = sys.executable
        main_py = _get_main_py_path()

        content = f"""[Unit]
Description=Sentinel Personal Laptop Security Monitor
After=network.target

[Service]
Type=simple
ExecStart={python_exe} {main_py} run
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""
        with open(service_path, "w", encoding="utf-8") as f:
            f.write(content)
        os.system("systemctl --user daemon-reload && systemctl --user enable sentinel.service")
        logger.success(f"Linux systemd user service enabled at {service_path}")
        return True
    except Exception as e:
        logger.warn(f"Failed to enable Linux autostart: {e}")
        return False


def _disable_linux() -> bool:
    try:
        service_path = _get_linux_service_path()
        if service_path.is_file():
            os.system("systemctl --user disable sentinel.service")
            service_path.unlink()
            logger.success("Linux systemd user service disabled.")
            return True
        return True
    except Exception as e:
        logger.warn(f"Failed to disable Linux autostart: {e}")
        return False


def _is_enabled_linux() -> bool:
    return _get_linux_service_path().is_file()
