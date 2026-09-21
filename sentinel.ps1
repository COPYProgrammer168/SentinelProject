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
    $pythonExe = $venvPythonw
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = $venvPython
    }
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = "python"
    }
    $argsString = "-m sentinel.main " + ($Arguments -join ' ')
    Start-Process -FilePath $pythonExe -ArgumentList $argsString -WindowStyle Hidden -NoNewWindow -RedirectStandardOutput NUL -RedirectStandardError NUL | Out-Null
} else {
    if (Test-Path $venvPython) {
        & $venvPython -m sentinel.main @Arguments
    } else {
        & python -m sentinel.main @Arguments
    }
}
