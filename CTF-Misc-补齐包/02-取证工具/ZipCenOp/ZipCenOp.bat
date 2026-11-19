@echo off
chcp 65001 >nul 2>nul
setlocal
title ZipCenOp - fake ZIP encryption (pseudo-encryption) fix
set "HERE=%~dp0"
if not exist "%HERE%ZipCenOp.jar" goto :nojar
where java >nul 2>nul || goto :nojava
if "%~1"=="" goto :usage
if exist "%~1" goto :drag
java -jar "%HERE%ZipCenOp.jar" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
echo   Recovering fake-encrypted zip: "%~1"
echo.
java -jar "%HERE%ZipCenOp.jar" r "%~1"

set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   ZipCenOp - fake ZIP encryption (pseudo-encryption) fix
echo   ------------------------------------------------------------
echo   Fix the classic 'zip is encrypted but no password works' trap.
echo.
echo     easiest: drag the .zip onto this .bat  -^> runs  r  (recover)
echo     from cmd:
echo       ZipCenOp.bat r file.zip   (remove fake encryption, file is modified!)
echo       ZipCenOp.bat e file.zip   (add fake encryption - for testing)
echo.
echo     Keep a backup copy before running  r ; it edits the zip in place.
echo.
echo   (no arguments given - showing the tool's own help)
echo.
java -jar "%HERE%ZipCenOp.jar"
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

:nojava
echo   [ERROR] java not found. Install Java 8+ (https://adoptium.net/).
if not defined CCM_NO_PAUSE pause >nul
exit /b 1

:nojar
echo   [ERROR] ZipCenOp.jar missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
