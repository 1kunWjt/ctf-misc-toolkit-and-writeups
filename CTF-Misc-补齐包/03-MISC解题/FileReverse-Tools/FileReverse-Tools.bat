@echo off
chcp 65001 >nul 2>nul
setlocal
title FileReverse-Tools - byte reversal / hex dump / unhex
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython
cd /d "%~dp0"
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
if exist "%~1" goto :drag
python "%~dp0FileReverse-Tools.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0FileReverse-Tools.py" -hh "%~1"

set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   FileReverse-Tools - byte reversal / hex dump / unhex
echo   ------------------------------------------------------------
echo   Byte-order tricks: hex dump, unhex, reverse, 2-byte swap.
echo.
echo     easiest: drag a file onto this .bat -^> hex dump (-hh)
echo     from cmd:
echo       FileReverse-Tools.bat -hh file.bin    file -^> hex TXT
echo       FileReverse-Tools.bat -uh file.txt    hex TXT -^> file
echo       FileReverse-Tools.bat -i  file.bin    2-byte read + invert
echo       FileReverse-Tools.bat -r  file.bin    hex reverse
echo       FileReverse-Tools.bat -re file.bin    2-byte reverse
echo       FileReverse-Tools.bat -a  file.bin    hex array TXT
echo       FileReverse-Tools.bat -b  file.txt    base64 TXT -^> file
echo.
echo     GUI version: FileReverse-Tools_Win_x64_1.02.exe (double click)
echo.
echo   (no arguments given - showing the tool's own help)
echo.
python "%~dp0FileReverse-Tools.py" -h
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
