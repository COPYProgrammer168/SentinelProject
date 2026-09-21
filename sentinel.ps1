<#
.SYNOPSIS
    Sentinel CLI Launcher for PowerShell
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments,
    [switch]$Hidden
)

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent -Path $MyInvocation.MyCommand.Definition }
$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"
$venvPythonw = Join-Path $scriptDir ".venv\Scripts\pythonw.exe"

if ($Hidden) {
    if (-not (Test-Path $venvPythonw)) {
        Write-Error "Hidden mode requires .venv\Scripts\pythonw.exe. Install pythonw or use visible mode."
        exit 1
    }
    Start-Process -FilePath $venvPythonw -ArgumentList ("--hidden " + ($Arguments -join ' ')) -WindowStyle Hidden -NoNewWindow | Out-Null
} else {
    if (Test-Path $venvPython) {
        & $venvPython -m sentinel.main @Arguments
    } else {
        & python -m sentinel.main @Arguments
    }
}
