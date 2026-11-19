@echo off
chcp 65001 >nul 2>nul
setlocal
title Deformed-Image-Restorer - brute force PNG width/height
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
if exist "%~1" goto :drag
python "%~dp0Deformed-Image-Restorer.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0Deformed-Image-Restorer.py" -i "%~1"

set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   Deformed-Image-Restorer - brute force PNG width/height
echo   ------------------------------------------------------------
echo   Repair a PNG whose IHDR width/height was tampered with (the classic
echo   'PNG shows half the image / CRC error' misc challenge).
echo.
echo     easiest: drag the broken .png onto this .bat -^> auto brute force (-i)
echo     from cmd:
echo       fixpng.bat -i broken.png          auto crack width/height and fix
echo       fixpng.bat -r 1200x800 broken.png  fix with a known size
echo.
echo     Output file is written next to the input image.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
python "%~dp0Deformed-Image-Restorer.py" -h
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
