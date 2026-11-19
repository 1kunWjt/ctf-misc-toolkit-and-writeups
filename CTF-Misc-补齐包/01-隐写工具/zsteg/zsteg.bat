@echo off
chcp 65001 >nul 2>nul
setlocal
title zsteg - PNG/BMP bit-plane and LSB scanner
set "HERE=%~dp0"
if not exist "%HERE%ruby\bin\ruby.exe" goto :missing
set "PATH=%HERE%ruby\bin;%PATH%"
set "GEM_HOME=%HERE%gems"
set "RUBYOPT=-EUTF-8"

if "%~1"=="" goto :usage
"%HERE%ruby\bin\ruby.exe" "%HERE%gems\bin\zsteg" %*
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   zsteg - PNG/BMP bit-plane and LSB scanner
echo   ------------------------------------------------------------
echo   Scan a PNG/BMP for hidden data in bit planes, LSB, channels.
echo.
echo     easiest: drag the image file onto this .bat
echo     from cmd:  zsteg.bat -a image.png        (full scan, most common)
echo                zsteg.bat -E "1b,rgb,lsb" image.png   (extract payload)
echo                zsteg.bat -o xy image.png       (change pixel order)
echo.
echo     If you see a 'gemrc' warning, ignore it - it does not affect results.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
"%HERE%ruby\bin\ruby.exe" "%HERE%gems\bin\zsteg" --help
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
