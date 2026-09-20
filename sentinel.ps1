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

if (-not (Test-Path $venvPython)) {
    $venvPython = "python"
}

if ($Hidden) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $venvPython
    $psi.Arguments = "-m sentinel.main " + ($Arguments -join ' ')
    $psi.WindowStyle = 'Hidden'
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $true
    [System.Diagnostics.Process]::Start($psi) | Out-Null
} else {
    & $venvPython -m sentinel.main @Arguments
}
