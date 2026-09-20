@echo off
setlocal
set SCRIPT_DIR=%~dp0
set VENV_PY=%SCRIPT_DIR%.venv\Scripts\python.exe

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
if exist "%VENV_PY%" (
    set HIDDEN_CMD=%VENV_PY%
) else (
    set HIDDEN_CMD=python
)

cscript //nologo "%SCRIPT_DIR%run-hidden.vbs" "%HIDDEN_CMD%" -m sentinel.main %HIDDEN_ARGS%
goto :eof
