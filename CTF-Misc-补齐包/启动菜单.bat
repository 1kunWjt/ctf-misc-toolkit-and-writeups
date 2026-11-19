@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
title CTF-Misc Toolkit - Menu
set "CCM_NO_PAUSE=1"

where powershell >nul 2>nul
if errorlevel 1 goto :nops

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0_menu.ps1" %*
if errorlevel 1 goto :fail
exit /b 0

:nops
echo.
echo   [ERROR] Windows PowerShell not found.
echo           This menu needs PowerShell (built into Windows 7+).
echo           You can still run each tool's .bat directly.
echo.
pause
exit /b 1

:fail
echo.
echo   The menu exited with an error. Press any key to close.
pause >nul
exit /b 1
