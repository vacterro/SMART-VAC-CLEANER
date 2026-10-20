@echo off
setlocal
cd /d "%~dp0"

if exist "SmartVACCleaner.exe" (
    start "" "SmartVACCleaner.exe" %*
    exit /b 0
)

where python3.12 >nul 2>&1
if %errorlevel% equ 0 (
    start "" python3.12 "_SMART_VAC_CLEANER.py" %*
    exit /b 0
)

if exist "%APPDATA%\uv\python\cpython-3.12.15-windows-x86_64-none\pythonw.exe" (
    start "" "%APPDATA%\uv\python\cpython-3.12.15-windows-x86_64-none\pythonw.exe" "_SMART_VAC_CLEANER.py" %*
    exit /b 0
)

start "" python "_SMART_VAC_CLEANER.py" %*
exit /b 0
