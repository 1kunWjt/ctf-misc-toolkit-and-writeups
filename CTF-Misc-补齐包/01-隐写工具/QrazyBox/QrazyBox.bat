@echo off
chcp 65001 >nul 2>nul
setlocal
title QrazyBox - offline QR code analyse / rebuild
set "HERE=%~dp0"
if not exist "%HERE%index.html" goto :nohtml
start "" "%HERE%index.html"
echo.
echo   Opens the offline QrazyBox page in your default browser.
echo   Use it to rebuild a damaged QR code: load the image, mark the
echo   three finder patterns, then decode / export the corrected QR.
echo   Everything runs locally - no internet needed.
echo.
echo   If nothing appeared, see 工具使用方法.md for troubleshooting.
if not defined CCM_NO_PAUSE pause >nul
exit /b 0

:nohtml
echo   [ERROR] index.html missing - the QrazyBox folder is incomplete.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
