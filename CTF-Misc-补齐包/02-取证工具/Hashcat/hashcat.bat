@echo off
chcp 65001 >nul 2>nul
setlocal
title Hashcat - GPU/CPU hash cracking
set "HERE=%~dp0"
if not exist "%HERE%hashcat.exe" goto :noexe
cd /d "%HERE%"

if "%~1"=="" goto :usage
"%HERE%hashcat.exe" %*
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   Hashcat - GPU/CPU hash cracking
echo   ------------------------------------------------------------
echo   Crack hashes with a wordlist (put rockyou.txt in this folder).
echo.
echo     typical (MD5 + rockyou):
echo       hashcat.bat -m 0 -a 0 hashes.txt rockyou.txt
echo     show already-cracked:      hashcat.bat -m 0 hashes.txt --show
echo     zip pseudo-encryption:     hashcat.bat -m 17200 hashes.txt rockyou.txt
echo     NTLM (windows):            hashcat.bat -m 1000 hashes.txt rockyou.txt
echo     benchmark first:           hashcat.bat -b
echo.
echo     -m = hash type, -a 0 = straight (wordlist) attack.
echo     Press  s  to see status,  p  to pause,  q  to quit.
echo     hash modes: https://hashcat.net/wiki/doku.php?id=example_hashes
echo.
echo   (no arguments given - showing the tool's own help)
echo.
"%HERE%hashcat.exe" --help | more
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
echo   [ERROR] hashcat.exe missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
