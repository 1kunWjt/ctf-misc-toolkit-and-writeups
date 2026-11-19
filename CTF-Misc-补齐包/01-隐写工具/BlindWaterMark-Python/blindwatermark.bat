@echo off
chcp 65001 >nul 2>nul
setlocal
title BlindWaterMark - blind image watermark encode / decode
set "HERE=%~dp0"
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if "%~1"=="" goto :usage
python "%~dp0bwmforpy3.py" %*
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   BlindWaterMark - blind image watermark encode / decode
echo   ------------------------------------------------------------
echo   Two steps, always: encode a watermark, or decode one.
echo.
echo     encode:  blindwatermark.bat encode  ^<image^> ^<watermark^> ^<output.png^>
echo       e.g.   blindwatermark.bat encode hui.png wm.png out.png
echo.
echo     decode:  blindwatermark.bat decode  ^<image^> ^<encoded.png^> ^<watermark_out.png^>
echo       e.g.   blindwatermark.bat decode hui.png out.png wm_from_out.png
echo.
echo     options: --alpha 3.0 (visibility/robustness), --seed 20160930
echo.
echo     In CTF: usually you get only the encoded image and must guess the
echo     algorithm/seed - try decode with the original if you have it.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
python "%~dp0bwmforpy3.py"
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
