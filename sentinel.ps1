<#
.SYNOPSIS
    Sentinel CLI Launcher for PowerShell
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent -Path $MyInvocation.MyCommand.Definition }
$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    & $venvPython -m sentinel.main @Arguments
} else {
    & python -m sentinel.main @Arguments
}
