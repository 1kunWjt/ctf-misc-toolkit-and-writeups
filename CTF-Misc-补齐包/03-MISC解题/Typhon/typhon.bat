@echo off
chcp 65001 >nul 2>nul
setlocal
title Typhon - pyjail / sandbox-escape helper
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
python "%~dp0typhon.py" %*
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   Typhon - pyjail / sandbox-escape helper
echo   ------------------------------------------------------------
echo   Auto-generate python-jail escape payloads.
echo.
echo     start the web UI (easiest, opens in browser):
echo       typhon.bat webui
echo     then paste the jail source / blacklist and let it search payloads.
echo.
echo     command line help:
echo       typhon.bat --help
echo.
echo   (no arguments given - showing the tool's own help)
echo.
python "%~dp0typhon.py" --help
set "RC=%ERRORLEVEL%"
goto :done
:done
call :finish
exit /b %RC%

:finish
if defined CCM_NO_PAUSE exit /b 0
echo.
echo   ------------------------------------------------------------
echo   Press any key to close this window...
pause >nul
exit /b 0

:nopython
echo   [ERROR] python not found on PATH.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
