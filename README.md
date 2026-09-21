# Sentinel — Personal Laptop Security Monitor (Phases 1 & 2 Prototype)

Lightweight, defensive background security monitor running locally on your laptop to detect anomalous network activity and unauthorized system changes.

---

## Quick Start

You can run Sentinel using the built-in launcher scripts:

### PowerShell (Windows)
```powershell
# Check status and baseline stats
.\sentinel.ps1 status

# Start real-time monitoring (visible terminal)
.\sentinel.ps1 run

# Start real-time monitoring (hidden, no terminal window)
.\sentinel.ps1 -Hidden run

# Run completely hidden without any PowerShell window (double-click this)
.\sentinel-hidden.vbs

# Start monitoring with immediate anomaly alerting (bypasses learning mode)
.\sentinel.ps1 run --immediate-mode

# View baseline allowlist of learned/allowed processes
.\sentinel.ps1 allowlist list

# View security alerts
.\sentinel.ps1 alerts

# Force an on-demand system change snapshot check
.\sentinel.ps1 snapshot

# Send a test desktop notification
.\sentinel.ps1 test-notify

# Open local review dashboard (Flask, binds to 127.0.0.1 only)
.\sentinel.ps1 dashboard

# Start always-on-top alert overlay widget (PyQt6)
.\sentinel.ps1 overlay

# Open desktop control panel GUI
.\sentinel.ps1 control-panel

# Enable background autostart on laptop boot/login (runs windowless in background)
.\sentinel.ps1 autostart enable

# Check autostart status
.\sentinel.ps1 autostart status

# Disable background autostart
.\sentinel.ps1 autostart disable
```

### Command Prompt / CMD (Windows)
```cmd
sentinel.bat status
sentinel.bat run
sentinel.bat allowlist list
sentinel.bat alerts
sentinel.bat dashboard
sentinel.bat overlay
sentinel.bat control-panel

:: Run hidden without terminal window (double-click sentinel-hidden.vbs)
sentinel-hidden.vbs
```

### Direct Python / Virtualenv
```powershell
# Option A: Activate virtual environment
.\.venv\Scripts\Activate.ps1
python -m sentinel.main run

# Option B: Run directly with venv python (requires '&' in PowerShell)
& .\.venv\Scripts\python.exe -m sentinel.main run

# Open dashboard
python -m sentinel.main dashboard

# Start overlay widget
python -m sentinel.main overlay

# Run without terminal window (PowerShell)
# Use the -Hidden switch with sentinel.ps1, or run pythonw.exe directly:
& .\.venv\Scripts\pythonw.exe -m sentinel.main run

### Rainmeter Skin
```powershell
# Copy the skin folder to your Rainmeter Skins directory:
# %APPDATA%\Rainmeter\Skins\SentinelStatus\
# Then refresh Rainmeter or load the skin manually.
```

---

## Features Implemented

### Phase 1: Core Network Monitor
- **Active Connection Polling**: Inspects active sockets (`psutil.net_connections(kind='inet')`) every N seconds (configurable with `--poll-interval`).
- **Learning Mode Baseline**: Automatically logs all active processes during an initial training period (default 7 days, configurable with `--learning-days`) and compiles a clean allowlist baseline in SQLite. No false alerts during learning mode.
- **Unauthorized Process Flagging**: Once learning mode is complete (or with `--immediate-mode`), flags any outbound connection from a process not in the baseline allowlist.
- **Idle State Anomaly Detection**: Uses OS idle input APIs (`GetLastInputInfo` on Windows, `IOKit` on macOS, `xprintidle`/mtime on Linux) to detect when the laptop is idle (no user keyboard/mouse activity). Flags external network connections initiated while away from the laptop.
- **Desktop Notifications**: Dispatches native Windows toasts (`win11toast` / PowerShell / `plyer`) with process name, remote IP, and severity. Rate-limited per target to avoid notification flooding.

### Phase 2: System Change Detector
- **Autostart / Persistence Snapshotting**:
  - Registry Run and RunOnce keys (`HKCU` and `HKLM`).
  - Windows Startup folders (`%APPDATA%` and `%ProgramData%`).
  - Running services (`psutil.win_service_iter()`).
  - Installed scheduled tasks (`schtasks /query /fo csv`).
- **Diff & Alert Engine**:
  - Automatically establishes initial baseline on first run.
  - On schedule or on-demand (`snapshot`), diffs current state against the previous snapshot in SQLite.
  - Flags any new or modified startup entries, services, or scheduled tasks immediately with high/critical severity alerts and desktop popups.

### Dashboard & Overlay
- **Local Review Dashboard** (`sentinel dashboard`): Flask-based single-page UI on `127.0.0.1:5000` with overview, period history, allowlist, network events, snapshots, alerts, and applications tabs.
- **Always-on-Top Overlay** (`sentinel overlay`): PyQt6 frameless widget (compact 320x180, expanded 500x400) with alert feed, traffic graph, approximate geo map, and attack counters. Writes `overlay_status.json` for Rainmeter integration.
- **Rainmeter Skin**: `rainmeter/SentinelStatus.ini` displays alerts fired, critical count, and flagged network events from the local dashboard API.

### Windhawk Mod — Taskbar Status Tint
- **Status Bridge**: Sentinel writes current severity to `C:\ProgramData\Sentinel\status.txt` (`NORMAL` / `WARNING` / `CRITICAL`).
- **Mod**: `windhawk-mods/sentinel-status/sentinel-status.cpp` hooks `DwmGetColorizationColor` in Explorer to tint the taskbar amber on WARNING and pulsing red on CRITICAL. Defaults to `NORMAL` if the status file is missing.

---

## Database Architecture

All data remains 100% local in SQLite (`sentinel.db` with WAL mode):
- `allowlist`: Baseline of authorized process names, connection counts, and manual tags.
- `network_events`: Detailed network activity history (process name, PID, local IP/port, remote IP/port, protocol, status, flagged reason).
- `system_snapshots`: Historical snapshots of startup items, services, and tasks.
- `alerts`: Security alert history with severity, timestamp, target item, remote IP, and message.
- `meta`: Configuration state (learning mode expiration, initialized timestamp).

---

## Running Unit Tests
```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
```
All 12 unit tests cover storage, OS collectors, idle detection, network monitoring, and system change detection.
