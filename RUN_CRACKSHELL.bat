\
@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0CrackShell.ps1"
if errorlevel 1 (
    echo.
    echo CrackShell closed with an error.
    pause
)
