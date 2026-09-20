# Sentinel Status — Windhawk Mod

Tints the Windows taskbar based on Sentinel's current severity status.

## Status File

Sentinel writes its current severity to:
```
C:\ProgramData\Sentinel\status.txt
```

Expected values:
- `NORMAL` — no tint
- `WARNING` — subtle amber tint
- `CRITICAL` — subtle red tint with slow pulse (~1.5s)

## Visual Effects

### Taskbar Accent Tint
- **NORMAL**: default Windows accent color, no modification
- **WARNING**: subtle amber overlay on the taskbar
- **CRITICAL**: subtle red overlay with a slow alpha pulse (1.5s cycle)

The tint is applied by hooking `DwmGetColorizationColor` in `explorer.exe`.
Only the alpha channel is modified, so your accent color remains visible
but carries the status hue.

### Safety
- Missing or invalid `status.txt` → treated as `NORMAL`
- If Sentinel is not running, the file may be stale or missing; the mod
  defaults to `NORMAL` and never crashes Explorer
- The mod only invalidates the taskbar window when the status actually
  changes, so CPU impact is negligible

## Building

Requires MSVC Build Tools with Windows SDK.

```cmd
build.bat
```

This produces `sentinel-status.dll`.

## Installing in Windhawk

1. Open Windhawk
2. Go to **Mods** → **Install from file**
3. Select `sentinel-status.dll`
4. Enable the mod
5. Restart Explorer if the taskbar does not update immediately

## Uninstalling

1. Open Windhawk
2. Go to **Mods**
3. Find **Sentinel Status Reactive Taskbar**
4. Click **Uninstall**

## Compatibility

- Windows 10 1809+
- Windows 11
- Requires DWM composition enabled (default on modern Windows)

## Source Layout

```
sentinel-status.cpp   - Mod source (hook + timer + color logic)
build.bat             - MSVC build script
README.md             - This file
```
