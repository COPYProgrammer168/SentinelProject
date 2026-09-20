@echo off
REM Build script for Sentinel Status Windhawk mod
REM Requires MSVC Build Tools with Windows SDK in PATH

echo Configuring Visual Studio environment...
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 2>nula
if errorlevel 1 (
    echo Could not find Visual Studio Build Tools.
    echo Please install "Desktop development with C++" workload from Visual Studio Installer.
    echo Or run this script from a "x64 Native Tools Command Prompt for VS 2022" window.
    pause
    exit /b 1
)

echo Building Sentinel Status Windhawk mod...

cl /EHsc /DUNICODE /D_UNICODE /W4 /O2 sentinel-status.cpp /link user32.lib gdi32.lib dwmapi.lib /OUT:sentinel-status.dll

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Build succeeded: sentinel-status.dll
pause
