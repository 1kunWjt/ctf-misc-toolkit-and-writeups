@echo off
chcp 65001 >nul 2>nul
setlocal
title Toolkit shell
set "TOOLKIT=%~dp0"
set "PATH=%TOOLKIT%01-隐写工具\zsteg\ruby\bin;%PATH%"
set "GEM_HOME=%TOOLKIT%01-隐写工具\zsteg\gems"
set "RUBYOPT=-EUTF-8"
set "PYTHONPATH=%TOOLKIT%05-密码学\pycryptodome\lib;%TOOLKIT%05-密码学\gmpy2\lib;%TOOLKIT%05-密码学\z3\lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
cd /d "%TOOLKIT%"
echo.
echo   Toolkit environment ready:
echo     ruby + zsteg   on PATH
echo     pycryptodome / gmpy2 / z3   on PYTHONPATH
echo   Current folder: %TOOLKIT%
echo   Type "exit" to close this shell.
echo.
cmd /k
