# -*- coding: utf-8 -*-
"""生成每个工具的启动脚本（.bat）与 Python 入口 shim。

设计要点（改之前先读）：
1. .bat 内容全部 **ASCII**，避免 cmd 代码页问题；中文说明放在
   `启动菜单.bat` / `_menu.ps1` / `工具使用方法.md` 里。
2. 每个 bat 都带 `chcp 65001` + PYTHONUTF8/PYTHONIOENCODING，让 Python 工具
   打印的中文不再乱码。
3. 每个 bat 结尾都会 pause（除非外面传了 CCM_NO_PAUSE=1），所以双击不会秒关。
4. 所有 bat 支持把文件/参数直接拖上去（%* 透传）。
"""
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    "CTF_TOOLKIT_ROOT", r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
)

# ---------------------------------------------------------------- bat 骨架

CLI_SKELETON = """@echo off
chcp 65001 >nul 2>nul
setlocal
title {title}
set "HERE=%~dp0"
{pre}
if "%~1"=="" goto :usage
{pick}
set "RC=%ERRORLEVEL%"
goto :done
:usage
echo.
echo   {title}
echo   ------------------------------------------------------------
{usage}
echo.
echo   (no arguments given - showing the tool's own help)
echo.
{demo}
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
"""

GUI_SKELETON = """@echo off
chcp 65001 >nul 2>nul
setlocal
title {title}
set "HERE=%~dp0"
{pre}
{action}
echo.
{note}
echo.
echo   If nothing appeared, see 工具使用方法.md for troubleshooting.
if not defined CCM_NO_PAUSE pause >nul
exit /b 0
"""


def _esc(text):
    """cmd 的 echo 里 < > | & ^ 都是特殊字符，必须转义，否则整条命令被截断。"""
    text = text.replace("^", "^^")
    for ch in ("<", ">", "|", "&"):
        text = text.replace(ch, "^" + ch)
    return text


def echo_block(lines):
    # 空行必须用 "echo."，否则 cmd 会打印 "ECHO is off."
    return "\n".join("echo." if ln == "" else "echo   " + _esc(ln) for ln in lines)


def cli(title, run="", usage=(), demo="", pre="", pick=None):
    return CLI_SKELETON.format(
        title=title,
        pre=pre,
        pick=pick or run,
        usage=echo_block(usage),
        demo=demo,
    )


def gui(title, action, note, pre=""):
    return GUI_SKELETON.format(title=title, pre=pre, action=action, note=echo_block(note))


PY_ENV = """set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
"""

# ---------------------------------------------------------------- 各工具 bat

BATS = {}

# 01 隐写 - zsteg（内置 ruby）
BATS[r"01-隐写工具\zsteg\zsteg.bat"] = cli(
    title="zsteg - PNG/BMP bit-plane and LSB scanner",
    pre="""if not exist "%HERE%ruby\\bin\\ruby.exe" goto :missing
set "PATH=%HERE%ruby\\bin;%PATH%"
set "GEM_HOME=%HERE%gems"
set "RUBYOPT=-EUTF-8\"
""",
    run='"%HERE%ruby\\bin\\ruby.exe" "%HERE%gems\\bin\\zsteg" %*',
    usage=[
        "Scan a PNG/BMP for hidden data in bit planes, LSB, channels.",
        "",
        "  easiest: drag the image file onto this .bat",
        "  from cmd:  zsteg.bat -a image.png        (full scan, most common)",
        "             zsteg.bat -E \"1b,rgb,lsb\" image.png   (extract payload)",
        "             zsteg.bat -o xy image.png       (change pixel order)",
        "",
        "  If you see a 'gemrc' warning, ignore it - it does not affect results.",
    ],
    demo='"%HERE%ruby\\bin\\ruby.exe" "%HERE%gems\\bin\\zsteg" --help',
)

# 01 隐写 - StegSolve（Java GUI）
BATS[r"01-隐写工具\StegSolve\StegSolve.bat"] = gui(
    title="StegSolve - channel / bit-plane / frame viewer",
    pre="""if not exist "%HERE%StegSolve-1.4.jar" goto :nojar
where javaw >nul 2>nul || goto :nojava""",
    action='start "" javaw -jar "%HERE%StegSolve-1.4.jar" %*',
    note=[
        "StegSolve window should open in a second.",
        "Drag the image into StegSolve, then use the arrows in 'Frame Browser'",
        "to switch R/G/B/A channels and bit planes.",
        "Tip: you can also drag a .png onto this .bat to preload it.",
        "",
        "Nothing opened? Java may be missing - open cmd and run:",
        "  java -jar \"%~dp0StegSolve-1.4.jar\"",
        "to see the real error.",
    ],
)
BATS[r"01-隐写工具\StegSolve\StegSolve.bat"] += """
:nojava
echo   [ERROR] javaw not found. Install Java (JRE 8+) first.
echo           https://adoptium.net/  or  winget install EclipseAdoptium.Temurin.17.JRE
goto :finish_gui

:nojar
echo   [ERROR] StegSolve-1.4.jar is missing in this folder.

:finish_gui
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 01 隐写 - TweakPNG（GUI，注意真实路径在 x64\x86 子目录）
BATS[r"01-隐写工具\TweakPNG\TweakPNG.bat"] = gui(
    title="TweakPNG - inspect / edit PNG chunks and recompute CRC",
    pre="""set "EXE=%HERE%x64\\tweakpng.exe"
if not exist "%EXE%" set "EXE=%HERE%x86\\tweakpng.exe"
if not exist "%EXE%" goto :noexe""",
    action='start "" "%EXE%" %*',
    note=[
        "TweakPNG window should open. Drag a .png into it, or drag a png onto this .bat.",
        "Use it to: view all chunks (tEXt/zTXt/iTXt/IHDR), edit them, and",
        "recompute CRC after changing a chunk - the classic 'fake CRC' fix.",
    ],
)
BATS[r"01-隐写工具\TweakPNG\TweakPNG.bat"] += """
:noexe
echo   [ERROR] tweakpng.exe not found under x64\\ or x86\\.
echo           Re-extract 01-隐写工具\\TweakPNG from the original package.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 01 隐写 - BlindWaterMark
BATS[r"01-隐写工具\BlindWaterMark-Python\blindwatermark.bat"] = cli(
    title="BlindWaterMark - blind image watermark encode / decode",
    pre=PY_ENV,
    run='python "%~dp0bwmforpy3.py" %*',
    usage=[
        "Two steps, always: encode a watermark, or decode one.",
        "",
        "  encode:  blindwatermark.bat encode  <image> <watermark> <output.png>",
        "    e.g.   blindwatermark.bat encode hui.png wm.png out.png",
        "",
        "  decode:  blindwatermark.bat decode  <image> <encoded.png> <watermark_out.png>",
        "    e.g.   blindwatermark.bat decode hui.png out.png wm_from_out.png",
        "",
        "  options: --alpha 3.0 (visibility/robustness), --seed 20160930",
        "",
        "  In CTF: usually you get only the encoded image and must guess the",
        "  algorithm/seed - try decode with the original if you have it.",
    ],
    demo='python "%~dp0bwmforpy3.py"',
)

# 01 隐写 - QrazyBox（离线网页工具）
BATS[r"01-隐写工具\QrazyBox\QrazyBox.bat"] = gui(
    title="QrazyBox - offline QR code analyse / rebuild",
    pre="""if not exist "%HERE%index.html" goto :nohtml""",
    action='start "" "%HERE%index.html"',
    note=[
        "Opens the offline QrazyBox page in your default browser.",
        "Use it to rebuild a damaged QR code: load the image, mark the",
        "three finder patterns, then decode / export the corrected QR.",
        "Everything runs locally - no internet needed.",
    ],
)
BATS[r"01-隐写工具\QrazyBox\QrazyBox.bat"] += """
:nohtml
echo   [ERROR] index.html missing - the QrazyBox folder is incomplete.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 02 取证 - Volatility3
BATS[r"02-取证工具\Volatility3\vol.bat"] = cli(
    title="Volatility 3 - memory forensics",
    pre="""where python >nul 2>nul || goto :nopython
rem keep volatility symbol / identifier cache inside this package
set "APPDATA=%~dp0cache"
if not exist "%APPDATA%" mkdir "%APPDATA%" >nul 2>nul
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
""",
    pick="""if exist "%~1" goto :drag
python "%~dp0vol.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0vol.py" -f "%~1" windows.info""",
    usage=[
        "Analyse a memory dump (Windows / Linux).",
        "",
        "  easiest: drag the memory image onto this .bat  -> runs windows.info",
        "  from cmd:",
        "    vol.bat -f mem.raw windows.info        (identify the image, run first)",
        "    vol.bat -f mem.raw windows.pslist      (process list)",
        "    vol.bat -f mem.raw windows.netscan     (connections)",
        "    vol.bat -f mem.raw windows.cmdline     (command lines)",
        "    vol.bat -f mem.raw windows.filescan | findstr flag",
        "",
        "  list all plugins:  vol.bat -f mem.raw --help",
        "  heavier plugins (malfind / handles) may take minutes - be patient.",
    ],
    demo='python "%~dp0vol.py" -h',
)
BATS[r"02-取证工具\Volatility3\vol.bat"] += """
:nopython
echo   [ERROR] python not found on PATH.
echo           Install Python 3.10+ and tick "Add python.exe to PATH".
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 02 取证 - MemProcFS
BATS[r"02-取证工具\MemProcFS\MemProcFS.bat"] = cli(
    title="MemProcFS - mount a memory dump as a virtual drive",
    pre="""if not exist "%HERE%MemProcFS.exe" goto :noexe""",
    pick="""if exist "%~1" goto :drag
"%HERE%MemProcFS.exe" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
if not exist "%~dp0mnt" mkdir "%~dp0mnt" >nul 2>nul
echo   Mounting "%~1" ... a virtual filesystem appears in:
echo     %~dp0mnt
echo   Press Ctrl+C in this window when you are done.
echo.
"%HERE%MemProcFS.exe" -device "%~1" -mount "%~dp0mnt"
""",
    usage=[
        "Turn a memory image into an explorable filesystem (no Volatility needed).",
        "",
        "  easiest: drag the memory image onto this .bat",
        "           -> mounts into  mnt\\  under this folder",
        "  from cmd:",
        "    MemProcFS.bat -device mem.raw -mount D:\\mnt",
        "    MemProcFS.bat -device mem.raw -mount mnt -forensic 1",
        "",
        "  After it starts, open the mnt folder: registry/, files/,",
        "  pid/, name/ ... everything is browsable in Explorer.",
        "  Requires Windows + the driver file already shipped in this folder.",
    ],
    demo='"%HERE%MemProcFS.exe"',
)

BATS[r"02-取证工具\MemProcFS\MemProcFS.bat"] += """
:noexe
echo   [ERROR] MemProcFS.exe missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 02 取证 - Hashcat
BATS[r"02-取证工具\Hashcat\hashcat.bat"] = cli(
    title="Hashcat - GPU/CPU hash cracking",
    pre="""if not exist "%HERE%hashcat.exe" goto :noexe
cd /d "%HERE%\"
""",
    run='"%HERE%hashcat.exe" %*',
    usage=[
        "Crack hashes with a wordlist (put rockyou.txt in this folder).",
        "",
        "  typical (MD5 + rockyou):",
        "    hashcat.bat -m 0 -a 0 hashes.txt rockyou.txt",
        "  show already-cracked:      hashcat.bat -m 0 hashes.txt --show",
        "  zip pseudo-encryption:     hashcat.bat -m 17200 hashes.txt rockyou.txt",
        "  NTLM (windows):            hashcat.bat -m 1000 hashes.txt rockyou.txt",
        "  benchmark first:           hashcat.bat -b",
        "",
        "  -m = hash type, -a 0 = straight (wordlist) attack.",
        "  Press  s  to see status,  p  to pause,  q  to quit.",
        "  hash modes: https://hashcat.net/wiki/doku.php?id=example_hashes",
    ],
    demo='"%HERE%hashcat.exe" --help | more',
)
BATS[r"02-取证工具\Hashcat\hashcat.bat"] += """
:noexe
echo   [ERROR] hashcat.exe missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 02 取证 - ZipCenOp（ZIP 伪加密）
BATS[r"02-取证工具\ZipCenOp\ZipCenOp.bat"] = cli(
    title="ZipCenOp - fake ZIP encryption (pseudo-encryption) fix",
    pre="""if not exist "%HERE%ZipCenOp.jar" goto :nojar
where java >nul 2>nul || goto :nojava""",
    pick="""if exist "%~1" goto :drag
java -jar "%HERE%ZipCenOp.jar" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
echo   Recovering fake-encrypted zip: "%~1"
echo.
java -jar "%HERE%ZipCenOp.jar" r "%~1"
""",
    usage=[
        "Fix the classic 'zip is encrypted but no password works' trap.",
        "",
        "  easiest: drag the .zip onto this .bat  -> runs  r  (recover)",
        "  from cmd:",
        "    ZipCenOp.bat r file.zip   (remove fake encryption, file is modified!)",
        "    ZipCenOp.bat e file.zip   (add fake encryption - for testing)",
        "",
        "  Keep a backup copy before running  r ; it edits the zip in place.",
    ],
    demo='java -jar "%HERE%ZipCenOp.jar"',
)
BATS[r"02-取证工具\ZipCenOp\ZipCenOp.bat"] += """
:nojava
echo   [ERROR] java not found. Install Java 8+ (https://adoptium.net/).
if not defined CCM_NO_PAUSE pause >nul
exit /b 1

:nojar
echo   [ERROR] ZipCenOp.jar missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 03 MISC - Ciphey（Rust 版 ciphey.exe）
BATS[r"03-MISC解题\Ciphey\ciphey.bat"] = cli(
    title="Ciphey - automatic cipher identification and decoding",
    pre="""if not exist "%HERE%ciphey.exe" goto :noexe""",
    pick="""set "A1=%~1"
if "%A1:~0,1%"=="-" goto :pass
"%HERE%ciphey.exe" -t "%*"
set "RC=%ERRORLEVEL%"
goto :done

:pass
"%HERE%ciphey.exe" %*""",
    usage=[
        "Give it a ciphertext string, it guesses the encoding/cipher and decodes it.",
        "",
        "  from cmd:",
        "    ciphey.bat aGVsbG8gd29ybGQ=",
        "    ciphey.bat -t \"Uryyb Jbeyq\"",
        "    ciphey.bat -t \"...\" -v -v      (more verbose)",
        "    ciphey.bat -t \"...\" -c 30      (cracking timeout seconds)",
        "",
        "  FIRST RUN: ciphey asks a few setup questions (tutorial? colour scheme?).",
        "  Just press Enter through them once - after that it decodes directly.",
        "",
        "  Note: input is TEXT, not a file. For files, extract strings first",
        "  (e.g. strings dump.bin) and paste the interesting part.",
    ],
    demo='"%HERE%ciphey.exe" --help',
)

BATS[r"03-MISC解题\Ciphey\ciphey.bat"] += """
:noexe
echo   [ERROR] ciphey.exe missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 03 MISC - CRC32-Tools
BATS[r"03-MISC解题\CRC32-Tools\CRC32-Tools.bat"] = cli(
    title="CRC32-Tools - zip CRC collision / 1-4 byte brute force",
    pre="""where python >nul 2>nul || goto :nopython
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
""",
    pick="""if exist "%~1" goto :drag
python "%~dp0CRC32-Tools.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0CRC32-Tools.py" -z "%~1"
""",
    usage=[
        "Break zip challenges whose CRC32 leaks the plaintext length.",
        "",
        "  easiest: drag the .zip onto this .bat -> lists CRC of every entry (-z)",
        "  from cmd:",
        "    CRC32-Tools.bat -z file.zip     list CRC32 of entries",
        "    CRC32-Tools.bat -1 file.zip     1-byte collision",
        "    CRC32-Tools.bat -2 file.zip     2-byte collision",
        "    CRC32-Tools.bat -3 file.zip     3-byte collision",
        "    CRC32-Tools.bat -4 file.zip     4-byte collision",
        "    (only 1-4 byte plaintexts are supported)",
    ],
    demo='python "%~dp0CRC32-Tools.py" -h',
)
BATS[r"03-MISC解题\CRC32-Tools\CRC32-Tools.bat"] += """
:nopython
echo   [ERROR] python not found on PATH.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 03 MISC - PNG 尺寸修复
BATS[r"03-MISC解题\PNG尺寸修复\fixpng.bat"] = cli(
    title="Deformed-Image-Restorer - brute force PNG width/height",
    pre="""where python >nul 2>nul || goto :nopython
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
""",
    pick="""if exist "%~1" goto :drag
python "%~dp0Deformed-Image-Restorer.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0Deformed-Image-Restorer.py" -i "%~1"
""",
    usage=[
        "Repair a PNG whose IHDR width/height was tampered with (the classic",
        "'PNG shows half the image / CRC error' misc challenge).",
        "",
        "  easiest: drag the broken .png onto this .bat -> auto brute force (-i)",
        "  from cmd:",
        "    fixpng.bat -i broken.png          auto crack width/height and fix",
        "    fixpng.bat -r 1200x800 broken.png  fix with a known size",
        "",
        "  Output file is written next to the input image.",
    ],
    demo='python "%~dp0Deformed-Image-Restorer.py" -h',
)
BATS[r"03-MISC解题\PNG尺寸修复\fixpng.bat"] += """
:nopython
echo   [ERROR] python not found on PATH.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 03 MISC - Typhon（pyjail）
BATS[r"03-MISC解题\Typhon\typhon.bat"] = cli(
    title="Typhon - pyjail / sandbox-escape helper",
    pre="""where python >nul 2>nul || goto :nopython
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
""",
    run='python "%~dp0typhon.py" %*',
    usage=[
        "Auto-generate python-jail escape payloads.",
        "",
        "  start the web UI (easiest, opens in browser):",
        "    typhon.bat webui",
        "  then paste the jail source / blacklist and let it search payloads.",
        "",
        "  command line help:",
        "    typhon.bat --help",
    ],
    demo='python "%~dp0typhon.py" --help',
)
BATS[r"03-MISC解题\Typhon\typhon.bat"] += """
:nopython
echo   [ERROR] python not found on PATH.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 03 MISC - FileReverse-Tools（原来没有 bat）
BATS[r"03-MISC解题\FileReverse-Tools\FileReverse-Tools.bat"] = cli(
    title="FileReverse-Tools - byte reversal / hex dump / unhex",
    pre="""where python >nul 2>nul || goto :nopython
cd /d "%~dp0"
set "PYTHONPATH=%~dp0lib;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
""",
    pick="""if exist "%~1" goto :drag
python "%~dp0FileReverse-Tools.py" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
python "%~dp0FileReverse-Tools.py" -hh "%~1"
""",
    usage=[
        "Byte-order tricks: hex dump, unhex, reverse, 2-byte swap.",
        "",
        "  easiest: drag a file onto this .bat -> hex dump (-hh)",
        "  from cmd:",
        "    FileReverse-Tools.bat -hh file.bin    file -> hex TXT",
        "    FileReverse-Tools.bat -uh file.txt    hex TXT -> file",
        "    FileReverse-Tools.bat -i  file.bin    2-byte read + invert",
        "    FileReverse-Tools.bat -r  file.bin    hex reverse",
        "    FileReverse-Tools.bat -re file.bin    2-byte reverse",
        "    FileReverse-Tools.bat -a  file.bin    hex array TXT",
        "    FileReverse-Tools.bat -b  file.txt    base64 TXT -> file",
        "",
        "  GUI version: FileReverse-Tools_Win_x64_1.02.exe (double click)",
    ],
    demo='python "%~dp0FileReverse-Tools.py" -h',
)
BATS[r"03-MISC解题\FileReverse-Tools\FileReverse-Tools.bat"] += """
:nopython
echo   [ERROR] python not found on PATH.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 04 - binwalk（内置 python 3.11）
BATS[r"04-文件与十六进制\binwalk\binwalk.bat"] = cli(
    title="binwalk - firmware / file signature scan and extract",
    pre="""if not exist "%HERE%python311\\python.exe" goto :nopy
set "PYTHONWARNINGS=ignore"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8\"
""",
    pick="""if exist "%~1" goto :drag
"%HERE%python311\\python.exe" "%HERE%lib\\src\\scripts\\binwalk" %*
set "RC=%ERRORLEVEL%"
goto :done

:drag
echo   Scanning "%~1" for embedded file signatures...
echo.
"%HERE%python311\\python.exe" "%HERE%lib\\src\\scripts\\binwalk" "%~1"
""",
    usage=[
        "Find file signatures inside a blob (png inside jpg, zip tail, squashfs...).",
        "",
        "  easiest: drag the suspicious file onto this .bat -> signature scan",
        "  from cmd:",
        "    binwalk.bat file.bin              signature scan",
        "    binwalk.bat -e file.bin          try to extract (needs 7z etc.)",
        "    binwalk.bat -A file.bin          opcode scan",
        "    binwalk.bat -R \"\\x89PNG\" file.bin   raw byte search",
        "",
        "  Note: -e on Windows is limited; for extraction prefer Bandizip or",
        "  dd-style slicing at the offset binwalk reports.",
    ],
    demo='"%HERE%python311\\python.exe" "%HERE%lib\\src\\scripts\\binwalk" --help',
)
BATS[r"04-文件与十六进制\binwalk\binwalk.bat"] += """
:nopy
echo   [ERROR] embedded python311 runtime missing in this folder.
if not defined CCM_NO_PAUSE pause >nul
exit /b 1
"""

# 05 - 密码学库环境
BATS[r"05-密码学\密码学库环境.bat"] = """@echo off
chcp 65001 >nul 2>nul
setlocal
title Crypto libs - pycryptodome / gmpy2 / z3
set "HERE=%~dp0"
where python >nul 2>nul || goto :nopython

set "PYTHONPATH=%HERE%pycryptodome\\lib;%HERE%gmpy2\\lib;%HERE%z3\\lib;%PYTHONPATH%"
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
"""

# 根 - 环境变量（改成直接开一个带环境的命令行）
ROOT_BAT = """@echo off
chcp 65001 >nul 2>nul
setlocal
title Toolkit shell
set "TOOLKIT=%~dp0"
set "PATH=%TOOLKIT%01-隐写工具\\zsteg\\ruby\\bin;%PATH%"
set "GEM_HOME=%TOOLKIT%01-隐写工具\\zsteg\\gems"
set "RUBYOPT=-EUTF-8"
set "PYTHONPATH=%TOOLKIT%05-密码学\\pycryptodome\\lib;%TOOLKIT%05-密码学\\gmpy2\\lib;%TOOLKIT%05-密码学\\z3\\lib;%PYTHONPATH%"
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
"""

PY_SHIMS = {
    r"02-取证工具\Volatility3\vol.py": '''# -*- coding: utf-8 -*-
"""volatility3 命令行入口（pip --target 装出来的 exe 不可直接跑，用这个）。"""
import sys
from volatility3.cli import main

if __name__ == "__main__":
    sys.argv[0] = "vol"
    sys.exit(main())
''',
    r"03-MISC解题\Typhon\typhon.py": '''# -*- coding: utf-8 -*-
"""Typhon (pyjail 自动化解题) 命令行入口。"""
import sys
from Typhon.cli import main

if __name__ == "__main__":
    sys.argv[0] = "typhonbreaker"
    sys.exit(main())
''',
}

NOTES = {
    r"02-取证工具\LovelyMem\启动说明.txt":
        "LovelyMem V2.5.0 内存取证一体化 GUI\n"
        "双击 Lovelymem-V2-2.5.0-windows-x64.exe 即可运行。\n"
        "内置 Volatility2 镜像、注册表/浏览器解析等，把内存镜像拖进去用。\n",
    r"03-MISC解题\CTFCrackTools\启动说明.txt":
        "CTFCrackTools-X v0.1.2（Windows x64）\n"
        "双击 ctfcracktools-x-0.1.2-windows-x64.exe 运行。\n",
    r"03-MISC解题\FileReverse-Tools\启动说明.txt":
        "FileReverse-Tools（文件反转/倒置）\n"
        "- 图形/发布版：FileReverse-Tools_Win_x64_1.02.exe\n"
        "- 命令行版：双击 FileReverse-Tools.bat（可直接把文件拖上去）\n",
    r"01-隐写工具\zsteg\兼容补丁说明.txt":
        "本目录的 zsteg 打了两个 Windows 兼容补丁（改的是 gems/zsteg-0.2.14/lib/zsteg/file_cmd.rb）：\n"
        "1) 找不到 file.exe / 无法创建管道时不再崩溃（stop! 里加了 nil 判断）\n"
        "2) 没有 file.exe 时改用内置的文件头识别（PNG/ZIP/JPEG/GZIP/文本等），\n"
        "   结果里 file: 后面照样会显示类型。\n"
        "想要最完整的效果：把 Git 的 usr\\bin 加入 PATH（里面有 file.exe）。\n",
    r"04-文件与十六进制\binwalk\兼容补丁说明.txt":
        "binwalk 是 v2.3.4（官方 Python 版）。\n"
        "Windows 兼容处理：\n"
        "1) 单独塞了一个 Python 3.11 嵌入式运行时（python311\\），因为 binwalk v2 用了\n"
        "   3.12 已删除的 imp / pwd 模块，装在本机 Python 3.14 上跑不起来。\n"
        "2) extractor.py 里 import pwd 改成 try/except（Windows 没有 pwd）。\n"
        "注意：解压（-e）依赖外部第三方工具（7z、unsquashfs 等），Windows 上建议\n"
        "直接用 Bandizip 或 Kali；扫描（签名定位）完全可用。\n",
}


def write(path, text, crlf=False):
    full = os.path.join(ROOT, path)
    d = os.path.dirname(full)
    if d:
        os.makedirs(d, exist_ok=True)
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    with open(full, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return full


def main():
    n = 0
    for rel, body in BATS.items():
        write(rel, body, crlf=True)
        n += 1
    for rel, body in PY_SHIMS.items():
        write(rel, body)
        n += 1
    for rel, body in NOTES.items():
        write(rel, body)
        n += 1
    write("环境变量.bat", ROOT_BAT, crlf=True)
    n += 1
    print("生成了 %d 个文件 (root: %s)" % (n, ROOT))


if __name__ == "__main__":
    main()
