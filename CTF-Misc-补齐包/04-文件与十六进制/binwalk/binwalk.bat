@echo off
chcp 65001 >nul 2>nul
setlocal
title binwalk - firmware / file signature scan and extract
set "HERE=%~dp0"
if not exist "%HERE%python311\python.exe" goto :nopy
set "PYTHONWARNINGS=ignore"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
if exist "%~1" goto :drag
"%HERE%python311\python.exe" "%HERE%lib\src\scripts\binwalk" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
echo   Scanning "%~1" for embedded file signatures...
echo.
"%HERE%python311\python.exe" "%HERE%lib\src\scripts\binwalk" "%~1"

set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   binwalk - firmware / file signature scan and extract
echo   ------------------------------------------------------------
echo   Find file signatures inside a blob (png inside jpg, zip tail, squashfs...).
echo.
echo     easiest: drag the suspicious file onto this .bat -^> signature scan
echo     from cmd:
echo       binwalk.bat file.bin              signature scan
echo       binwalk.bat -e file.bin          try to extract (needs 7z etc.)
echo       binwalk.bat -A file.bin          opcode scan
echo       binwalk.bat -R "\x89PNG" file.bin   raw byte search
echo.
echo     Note: -e on Windows is limited; for extraction prefer Bandizip or
echo     dd-style slicing at the offset binwalk reports.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
"%HERE%python311\python.exe" "%HERE%lib\src\scripts\binwalk" --help
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

:nopy
echo   [ERROR] embedded python311 runtime missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
