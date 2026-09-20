@echo off
REM Build script for Sentinel Status Windhawk mod
REM Requires MSVC Build Tools with Windows SDK in PATH

echo Building Sentinel Status Windhawk mod...

cl /EHsc /DUNICODE /D_UNICODE /W4 /O2 sentinel-status.cpp /link user32.lib gdi32.lib dwmapi.lib /OUT:sentinel-status.dll

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Build succeeded: sentinel-status.dll
pause
