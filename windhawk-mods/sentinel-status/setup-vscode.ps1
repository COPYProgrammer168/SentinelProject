# Auto-configure VS Code C/C++ IntelliSense for Sentinel Status Windhawk mod
# Run this from the windhawk-mods/sentinel-status directory if IntelliSense shows errors

$ErrorActionPreference = 'SilentlyContinue'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Host "vswhere.exe not found. Please install Visual Studio Installer or manually configure .vscode/c_cpp_properties.json"
    exit 1
}

$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) {
    Write-Host "No Visual Studio with C++ tools found. Please install 'Desktop development with C++' workload."
    exit 1
}

$vcTools = Get-ChildItem "$vsInstall\VC\Tools\MSVC" -Directory | Sort-Object Name -Descending | Select-Object -First 1
if (-not $vcTools) {
    Write-Host "Could not find VC Tools directory."
    exit 1
}

$vcToolsPath = $vcTools.FullName
$hostArch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

$windowsKits = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Include" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
$winSdkVersion = if ($windowsKits) { $windowsKits.Name } else { "10.0.22000.0" }
$winSdkPath = "C:/Program Files (x86)/Windows Kits/10/Include/$winSdkVersion"

$includePaths = @(
    "${workspaceFolder}/**",
    "$winSdkPath/um",
    "$winSdkPath/shared",
    "$winSdkPath/winrt",
    "$winSdkPath/cppwinrt",
    "$vcToolsPath/include",
    "$vsInstall/VC/Auxiliary/VS/include"
) -join "`n                "

$compilerPath = "$vcToolsPath/bin/Host$hostArch/$hostArch/cl.exe"

$json = @"
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                $includePaths
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE"
            ],
            "compilerPath": "$compilerPath",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-msvc-x64"
        }
    ],
    "version": 4
}
"@

$vscodeDir = ".vscode"
if (-not (Test-Path $vscodeDir)) {
    New-Item -ItemType Directory -Path $vscodeDir | Out-Null
}

$json | Out-File -FilePath "$vscodeDir\c_cpp_properties.json" -Encoding utf8
Write-Host "Created $vscodeDir\c_cpp_properties.json with detected paths:"
Write-Host "  Windows SDK: $winSdkVersion"
Write-Host "  MSVC Tools: $vcToolsPath"
Write-Host "  Compiler: $compilerPath"
