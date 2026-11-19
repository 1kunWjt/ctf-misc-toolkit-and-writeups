@echo off
chcp 65001 >nul 2>nul
setlocal
title Ciphey - automatic cipher identification and decoding
set "HERE=%~dp0"
if not exist "%HERE%ciphey.exe" goto :noexe
if "%~1"=="" goto :usage
set "A1=%~1"
if "%A1:~0,1%"=="-" goto :pass
"%HERE%ciphey.exe" -t "%*"
set "RC=%ERRORLEVEL%"
goto :done

:pass
"%HERE%ciphey.exe" %*
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   Ciphey - automatic cipher identification and decoding
echo   ------------------------------------------------------------
echo   Give it a ciphertext string, it guesses the encoding/cipher and decodes it.
echo.
echo     from cmd:
echo       ciphey.bat aGVsbG8gd29ybGQ=
echo       ciphey.bat -t "Uryyb Jbeyq"
echo       ciphey.bat -t "..." -v -v      (more verbose)
echo       ciphey.bat -t "..." -c 30      (cracking timeout seconds)
echo.
echo     FIRST RUN: ciphey asks a few setup questions (tutorial? colour scheme?).
echo     Just press Enter through them once - after that it decodes directly.
echo.
echo     Note: input is TEXT, not a file. For files, extract strings first
echo     (e.g. strings dump.bin) and paste the interesting part.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
"%HERE%ciphey.exe" --help
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
echo   [ERROR] ciphey.exe missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
