# build-windows.ps1
# Packages exe-triage as a standalone Windows executable using PyInstaller.
#
# Prerequisites:
#   - Python 3.11+ installed and on PATH
#   - Run from the project root directory
#
# Usage:
#   .\scripts\build-windows.ps1
#   .\scripts\build-windows.ps1 -Version "1.2.0"

param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$OutputName = "exe-triage-v$Version-windows-x64"

Write-Host "==> Installing build dependencies..."
python -m pip install -e ".[build]" --quiet

Write-Host "==> Running PyInstaller..."
pyinstaller exe_triage.spec --noconfirm

if (-not (Test-Path "dist\exe-triage\exe-triage.exe")) {
    Write-Error "Build failed: exe-triage.exe not found in dist\exe-triage\"
    exit 1
}

Write-Host "==> Packaging as zip..."
$ZipPath = "dist\$OutputName.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path "dist\exe-triage" -DestinationPath $ZipPath

Write-Host ""
Write-Host "Build complete."
Write-Host "  Executable : dist\exe-triage\exe-triage.exe"
Write-Host "  Release zip: $ZipPath"
Write-Host ""
Write-Host "To test the build:"
Write-Host "  .\dist\exe-triage\exe-triage.exe --help"
