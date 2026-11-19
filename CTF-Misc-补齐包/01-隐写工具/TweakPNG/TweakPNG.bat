@echo off
chcp 65001 >nul 2>nul
setlocal
title TweakPNG - inspect / edit PNG chunks and recompute CRC
set "HERE=%~dp0"
set "EXE=%HERE%x64\tweakpng.exe"
if not exist "%EXE%" set "EXE=%HERE%x86\tweakpng.exe"
if not exist "%EXE%" goto :noexe
start "" "%EXE%" %*
echo.
echo   TweakPNG window should open. Drag a .png into it, or drag a png onto this .bat.
echo   Use it to: view all chunks (tEXt/zTXt/iTXt/IHDR), edit them, and
echo   recompute CRC after changing a chunk - the classic 'fake CRC' fix.
echo.
echo   If nothing appeared, see 工具使用方法.md for troubleshooting.
if not defined CCM_NO_PAUSE pause >nul
exit /b 0

:noexe
echo   [ERROR] tweakpng.exe not found under x64\ or x86\.
echo           Re-extract 01-隐写工具\TweakPNG from the original package.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
