@echo off
chcp 65001 >nul 2>nul
setlocal
title CRC32-Tools - zip CRC collision / 1-4 byte brute force
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
if exist "%~1" goto :drag
python "%~dp0CRC32-Tools.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0CRC32-Tools.py" -z "%~1"

set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   CRC32-Tools - zip CRC collision / 1-4 byte brute force
echo   ------------------------------------------------------------
echo   Break zip challenges whose CRC32 leaks the plaintext length.
echo.
echo     easiest: drag the .zip onto this .bat -^> lists CRC of every entry (-z)
echo     from cmd:
echo       CRC32-Tools.bat -z file.zip     list CRC32 of entries
echo       CRC32-Tools.bat -1 file.zip     1-byte collision
echo       CRC32-Tools.bat -2 file.zip     2-byte collision
echo       CRC32-Tools.bat -3 file.zip     3-byte collision
echo       CRC32-Tools.bat -4 file.zip     4-byte collision
echo       (only 1-4 byte plaintexts are supported)
echo.
echo   (no arguments given - showing the tool's own help)
echo.
python "%~dp0CRC32-Tools.py" -h
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
