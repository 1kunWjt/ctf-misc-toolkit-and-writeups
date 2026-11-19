@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title CyberChef Local Server

echo.
echo   ============================================
echo    CyberChef Local Edition  (v11.5.0)
echo   ============================================
echo.

where node >nul 2>nul
if %errorlevel%==0 goto usenode

where python >nul 2>nul
if %errorlevel%==0 goto usepython

where py >nul 2>nul
if %errorlevel%==0 goto usepy

echo   [ERROR] Neither Node.js nor Python was found.
echo.
echo   Please install Node.js from https://nodejs.org/
echo   then double-click this file again.
echo.
pause
exit /b 1

:usenode
node "%~dp0server.js" %*
if errorlevel 1 (
    echo.
    echo   Server exited with an error. Press any key to close.
    pause >nul
)
exit /b 0

:usepython
echo   Node.js not found, falling back to Python HTTP server on port 8787...
start "CyberChef Server (Python)" /min cmd /c "python -m http.server 8787 --bind 127.0.0.1"
timeout /t 2 >nul
start "" "http://127.0.0.1:8787/CyberChef.html"
echo.
echo   Server is running in a minimized window (port 8787).
echo   Close that minimized window to stop the server.
echo.
pause
exit /b 0

:usepy
echo   Node.js not found, falling back to Python launcher on port 8787...
start "CyberChef Server (Python)" /min cmd /c "py -m http.server 8787 --bind 127.0.0.1"
timeout /t 2 >nul
start "" "http://127.0.0.1:8787/CyberChef.html"
echo.
echo   Server is running in a minimized window (port 8787).
echo   Close that minimized window to stop the server.
echo.
pause
exit /b 0
