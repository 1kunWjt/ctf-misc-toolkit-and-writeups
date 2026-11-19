@echo off
chcp 65001 >nul 2>nul
setlocal
title Volatility 3 - memory forensics
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython
rem keep volatility symbol / identifier cache inside this package
set "APPDATA=%~dp0cache"
if not exist "%APPDATA%" mkdir "%APPDATA%" >nul 2>nul
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
if exist "%~1" goto :drag
python "%~dp0vol.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0vol.py" -f "%~1" windows.info
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   Volatility 3 - memory forensics
echo   ------------------------------------------------------------
echo   Analyse a memory dump (Windows / Linux).
echo.
echo     easiest: drag the memory image onto this .bat  -^> runs windows.info
echo     from cmd:
echo       vol.bat -f mem.raw windows.info        (identify the image, run first)
echo       vol.bat -f mem.raw windows.pslist      (process list)
echo       vol.bat -f mem.raw windows.netscan     (connections)
echo       vol.bat -f mem.raw windows.cmdline     (command lines)
echo       vol.bat -f mem.raw windows.filescan ^| findstr flag
echo.
echo     list all plugins:  vol.bat -f mem.raw --help
echo     heavier plugins (malfind / handles) may take minutes - be patient.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
python "%~dp0vol.py" -h
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
echo           Install Python 3.10+ and tick "Add python.exe to PATH".
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
