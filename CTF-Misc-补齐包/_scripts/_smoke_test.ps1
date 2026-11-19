param(
    [string]$Root = "D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
)
$ErrorActionPreference = 'Continue'
$log = Join-Path $Root '.tmp_test'
if (Test-Path $log) { Remove-Item $log -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $log | Out-Null

$cases = @(
    @{ n = '01_zsteg';        d = '01-隐写工具\zsteg';                     b = 'zsteg.bat';                   a = '-a "..\TweakPNG\sample.png"'; t = 120 },
    @{ n = '02_stegsolve';    d = '01-隐写工具\StegSolve';                  b = 'StegSolve.bat';               a = '';  t = 30 },
    @{ n = '03_tweakpng';     d = '01-隐写工具\TweakPNG';                   b = 'TweakPNG.bat';                a = 'sample.png'; t = 30 },
    @{ n = '04_qrazybox';     d = '01-隐写工具\QrazyBox';                   b = 'QrazyBox.bat';                a = '';  t = 20 },
    @{ n = '05_blindwm';      d = '01-隐写工具\BlindWaterMark-Python';      b = 'blindwatermark.bat';          a = '';  t = 60 },
    @{ n = '06_vol';          d = '02-取证工具\Volatility3';                b = 'vol.bat';                     a = '--help'; t = 90 },
    @{ n = '07_memprocfs';    d = '02-取证工具\MemProcFS';                  b = 'MemProcFS.bat';               a = '';  t = 40 },
    @{ n = '08_zipcenop';     d = '02-取证工具\ZipCenOp';                   b = 'ZipCenOp.bat';                a = '';  t = 40 },
    @{ n = '09_hashcat';      d = '02-取证工具\Hashcat';                    b = 'hashcat.bat';                 a = '--version'; t = 60 },
    @{ n = '10_ciphey';       d = '03-MISC解题\Ciphey';                     b = 'ciphey.bat';                  a = '-t "aGVsbG8gd29ybGQ="'; t = 90 },
    @{ n = '11_crc32';        d = '03-MISC解题\CRC32-Tools';                b = 'CRC32-Tools.bat';             a = '-z 4Byte-Demo.zip'; t = 90 },
    @{ n = '12_fixpng';       d = '03-MISC解题\PNG尺寸修复';                 b = 'fixpng.bat';                  a = '-h'; t = 60 },
    @{ n = '13_typhon';       d = '03-MISC解题\Typhon';                     b = 'typhon.bat';                  a = '--help'; t = 60 },
    @{ n = '14_filereverse';  d = '03-MISC解题\FileReverse-Tools';          b = 'FileReverse-Tools.bat';       a = '-hh "..\PNG尺寸修复\img\1.png"'; t = 60 },
    @{ n = '15_binwalk';      d = '04-文件与十六进制\binwalk';               b = 'binwalk.bat';                 a = '"..\..\01-隐写工具\TweakPNG\sample.png"'; t = 90 },
    @{ n = '16_typhon_none';  d = '03-MISC解题\Typhon';                     b = 'typhon.bat';                  a = '';  t = 60 }
)

foreach ($c in $cases) {
    $dir = Join-Path $Root $c.d
    $bat = Join-Path $dir $c.b
    $cmdFile = Join-Path $log ($c.n + '.cmd')
    $outFile = Join-Path $log ($c.n + '.out.txt')
    $body = "@echo off`r`nchcp 65001 >nul`r`ncd /d `"$dir`"`r`ncall `"$bat`" $($c.a)`r`nexit /b %ERRORLEVEL%`r`n"
    [System.IO.File]::WriteAllText($cmdFile, $body, (New-Object System.Text.UTF8Encoding($false)))

    $job = Start-Job -ScriptBlock {
        param($cf, $of)
        & cmd /c "`"$cf`" > `"$of`" 2>&1"
        return $LASTEXITCODE
    } -ArgumentList $cmdFile, $outFile

    Write-Host ''
    Write-Host ('##### ' + $c.n + '   [' + $c.b + ' ' + $c.a + ']') -ForegroundColor Cyan
    if (Wait-Job $job -Timeout $c.t) {
        $code = Receive-Job $job
        Write-Host ("  exit=" + $code)
        $txt = if (Test-Path $outFile) { [System.IO.File]::ReadAllText($outFile, [System.Text.Encoding]::UTF8) } else { '' }
        $t = $txt.Trim()
        if ($t) { ($t -split "`r?`n" | Select-Object -First 9) | ForEach-Object { '  | ' + $_.TrimEnd() } }
        else { Write-Host '  (no output)' }
    } else {
        Write-Host ("  TIMEOUT " + $c.t + "s (GUI 工具属正常)")
        Stop-Job $job
    }
    Remove-Job $job -Force
}
Write-Host ''
Write-Host 'done' -ForegroundColor Green
