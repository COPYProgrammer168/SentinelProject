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

## VS Code IntelliSense

If VS Code shows errors like `'Windows.h' file not found` or `Unknown type name 'DWORD'`, your C/C++ extension doesn't know where the Windows SDK is.

### Option A: Auto-setup

```powershell
.\setup-vscode.ps1
```

### Option B: Manual setup

1. Install **Visual Studio Build Tools** with the **"Desktop development with C++"** workload.
2. In VS Code, open the command palette (`Ctrl+Shift+P`) → **C/C++: Edit Configurations (JSON)**.
3. Update `includePath` and `compilerPath` to match your installation, for example:

```json
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**",
                "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22000.0/um",
                "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22000.0/shared",
                "C:/Program Files (x86)/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.38.33130/include"
            ],
            "defines": ["_DEBUG", "UNICODE", "_UNICODE"],
            "compilerPath": "C:/Program Files (x86)/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.38.33130/bin/Hostx64/x64/cl.exe",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-msvc-x64"
        }
    ],
    "version": 4
}
```

4. Adjust the Windows SDK version (`10.0.22000.0`) and MSVC path (`14.38.33130`) to match what you have installed.
5. Reload VS Code.

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

## Troubleshooting

### Windhawk editor shows errors like `Expected function body` or `Unknown type name PWH_MOD_MODULE_CONTEXT`

These are **editor-only diagnostics**. The Windhawk editor uses clang for syntax checking, but its internal include paths may not fully match Windhawk's own build environment. The mod still compiles and loads correctly inside Windhawk.

If you want cleaner editor experience:
- Make sure Windhawk itself is up to date
- Try restarting the Windhawk editor
- Ignore diagnostics inside the `WH_MOD_METADATA_*` block and `WhModInit`/`WhModUninit` signatures; those are Windhawk API specifics the editor sometimes misparses

### Taskbar color doesn't change

- Restart Explorer after enabling the mod
- Make sure `C:\ProgramData\Sentinel\status.txt` exists and contains `NORMAL`, `WARNING`, or `CRITICAL`
- Check that Sentinel is running and writing status updates

## Source Layout

```
sentinel-status.cpp     - Mod source (hook + timer + color logic)
build.bat               - MSVC build script
setup-vscode.ps1        - Auto-configure VS Code IntelliSense
README.md               - This file
```
