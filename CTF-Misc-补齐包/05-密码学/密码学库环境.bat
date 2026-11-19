@echo off
chcp 65001 >nul 2>nul
setlocal
title Crypto libs - pycryptodome / gmpy2 / z3
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython

set "PYTHONPATH=%HERE%pycryptodome\lib;%HERE%gmpy2\lib;%HERE%z3\lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo.
echo   Crypto libraries are now on PYTHONPATH:
echo     pycryptodome   (AES/RSA/ECC/hash)
echo     gmpy2          (big int, iroot, invert)
echo     z3-solver      (constraint solving)
echo.
python -c "import Crypto,gmpy2,z3;print('  pycryptodome',Crypto.__version__);print('  gmpy2',gmpy2.version());print('  z3',z3.get_version_string())"
echo.
echo   This window is a python-ready shell. Try:
echo     python -c "from Crypto.Util.number import *; print(long_to_bytes(0x68656c6c6f))"
echo     python your_solve.py
echo   Type "exit" to close.
echo.
cmd /k
goto :eof

:nopython
echo   [ERROR] python not found on PATH.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
