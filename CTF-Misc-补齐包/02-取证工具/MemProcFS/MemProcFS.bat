@echo off
chcp 65001 >nul 2>nul
setlocal
title MemProcFS - mount a memory dump as a virtual drive
set "HERE=%~dp0"
if not exist "%HERE%MemProcFS.exe" goto :noexe
if "%~1"=="" goto :usage
if exist "%~1" goto :drag
"%HERE%MemProcFS.exe" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
if not exist "%~dp0mnt" mkdir "%~dp0mnt" >nul 2>nul
echo   Mounting "%~1" ... a virtual filesystem appears in:
echo     %~dp0mnt
echo   Press Ctrl+C in this window when you are done.
echo.
"%HERE%MemProcFS.exe" -device "%~1" -mount "%~dp0mnt"

set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   MemProcFS - mount a memory dump as a virtual drive
echo   ------------------------------------------------------------
echo   Turn a memory image into an explorable filesystem (no Volatility needed).
echo.
echo     easiest: drag the memory image onto this .bat
echo              -^> mounts into  mnt\  under this folder
echo     from cmd:
echo       MemProcFS.bat -device mem.raw -mount D:\mnt
echo       MemProcFS.bat -device mem.raw -mount mnt -forensic 1
echo.
echo     After it starts, open the mnt folder: registry/, files/,
echo     pid/, name/ ... everything is browsable in Explorer.
echo     Requires Windows + the driver file already shipped in this folder.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
"%HERE%MemProcFS.exe"
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

:noexe
echo   [ERROR] MemProcFS.exe missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
