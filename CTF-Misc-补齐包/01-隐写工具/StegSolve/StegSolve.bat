@echo off
chcp 65001 >nul 2>nul
setlocal
title StegSolve - channel / bit-plane / frame viewer
set "HERE=%~dp0"
if not exist "%HERE%StegSolve-1.4.jar" goto :nojar
where javaw >nul 2>nul || goto :nojava
start "" javaw -jar "%HERE%StegSolve-1.4.jar" %*
echo.
echo   StegSolve window should open in a second.
echo   Drag the image into StegSolve, then use the arrows in 'Frame Browser'
echo   to switch R/G/B/A channels and bit planes.
echo   Tip: you can also drag a .png onto this .bat to preload it.
echo.
echo   Nothing opened? Java may be missing - open cmd and run:
echo     java -jar "%~dp0StegSolve-1.4.jar"
echo   to see the real error.
echo.
echo   If nothing appeared, see 工具使用方法.md for troubleshooting.
if not defined CCM_NO_PAUSE pause >nul
exit /b 0

:nojava
echo   [ERROR] javaw not found. Install Java (JRE 8+) first.
echo           https://adoptium.net/  or  winget install EclipseAdoptium.Temurin.17.JRE
goto :finish_gui

:nojar
echo   [ERROR] StegSolve-1.4.jar is missing in this folder.

:finish_gui
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
