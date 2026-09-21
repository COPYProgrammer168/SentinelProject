@echo off
setlocal
set SCRIPT_DIR=%~dp0
set VENV_PY=%SCRIPT_DIR%.venv\Scripts\python.exe
set VENV_PYW=%SCRIPT_DIR%.venv\Scripts\pythonw.exe

if "%1"=="--hidden" goto :hidden
if "%1"=="-hidden" goto :hidden

if exist "%VENV_PY%" (
    "%VENV_PY%" -m sentinel.main %*
) else (
    python -m sentinel.main %*
)
goto :eof

:hidden
shift
set HIDDEN_ARGS=%*
if not exist "%VENV_PYW%" (
    echo Hidden mode requires .venv\Scripts\pythonw.exe.>&2
    exit /b 1
)
start "" /b ""%VENV_PYW%"" --hidden -m sentinel.main %HIDDEN_ARGS% >NUL 2>&1
goto :eof
