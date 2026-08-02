# Build SmartVACCleaner.exe (PyInstaller onefile)
# Usage: powershell -ExecutionPolicy Bypass -File build_exe.ps1

$ErrorActionPreference = "Stop"

python -m pip install --quiet pyinstaller
if (-not $?) { throw "pyinstaller install failed" }

python -m PyInstaller --onefile --console --clean --noconfirm `
    --name SmartVACCleaner `
    --collect-data customtkinter `
    _SMART_VAC_CLEANER.py
if (-not $?) { throw "pyinstaller build failed" }

Write-Host ""
Write-Host "OK: dist\SmartVACCleaner.exe"
