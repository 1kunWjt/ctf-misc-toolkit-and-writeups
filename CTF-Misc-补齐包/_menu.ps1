# CTF-Misc 工具包 · 交互菜单
# 由 启动菜单.bat 调用。全部逻辑集中在 _scripts/gen_menu.py 生成之外，本文件可自由修改。
$ErrorActionPreference = 'Continue'

$Root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$env:CCM_NO_PAUSE = '1'   # 菜单里跑工具时不要工具自己再 pause，统一由菜单控制

# ------------------------------------------------------------------ 工具清单
$Tools = @(
    # ---------------- 01 隐写
    [pscustomobject]@{
        Id = 1; Cat = '隐写'; Name = 'zsteg'; Kind = 'cli'; Mode = 'file'
        Dir = '01-隐写工具\zsteg'; Cmd = 'zsteg.bat'
        Desc = 'PNG/BMP 位平面 / LSB 隐写全量扫描（内置 Ruby，离线可用）'
        Template = '-a "{0}" {1}'; Extra = ''
        Usage = @('-a                    全量扫描（CTF 里先跑这个）',
                  '-E "1b,rgb,lsb"       只提取某个通道组合',
                  '-o xy                 换像素遍历顺序（x 先还是 y 先）')
        Tips = @('先 -a，看到可疑的 b1/rgb/lsb 行列后再用 -E 精确提取。',
                 'gemrc 权限警告是正常现象，不影响结果。')
    },
    [pscustomobject]@{
        Id = 2; Cat = '隐写'; Name = 'StegSolve'; Kind = 'gui'
        Dir = '01-隐写工具\StegSolve'; Cmd = 'StegSolve.bat'
        Desc = 'Java 图形工具：切 R/G/B/A 通道、位平面、帧，肉眼找隐写'
        Usage = @('打开后把图片拖进窗口，用下方箭头切通道 / 位平面。')
        Tips = @('双击 bat 若没反应，说明 Java 有问题：在 cmd 里跑',
                 '  java -jar StegSolve-1.4.jar  可以看到真实报错。')
    },
    [pscustomobject]@{
        Id = 3; Cat = '隐写'; Name = 'TweakPNG'; Kind = 'gui'
        Dir = '01-隐写工具\TweakPNG'; Cmd = 'TweakPNG.bat'
        Desc = 'PNG chunk 级查看 / 修改 / 重算 CRC（假 CRC、tEXt 藏数据）'
        Usage = @('打开后拖入 png，逐个 chunk 看 tEXt/zTXt/iTXt/IHDR。')
        Tips = @('改完 chunk 记得让工具重算 CRC，否则图片会打不开。',
                 '(原来的 bat 指向了不存在的路径，已在本版修好)')
    },
    [pscustomobject]@{
        Id = 4; Cat = '隐写'; Name = 'BlindWaterMark'; Kind = 'cli'; Mode = 'args'
        Dir = '01-隐写工具\BlindWaterMark-Python'; Cmd = 'blindwatermark.bat'
        Desc = '盲水印：encode 编码 / decode 解码（图片隐写常见套路）'
        Template = '{0}'; Extra = ''
        Usage = @('encode hui.png wm.png out.png      把水印打进图片',
                  'decode hui.png out.png wm_out.png  从图片里还原水印',
                  '--alpha 3.0 / --seed 20160930      控制强度与随机种子')
        Tips = @('比赛里通常只给一张合成图：先用 decode 拿原图当参照试。')
    },
    [pscustomobject]@{
        Id = 5; Cat = '隐写'; Name = 'QrazyBox'; Kind = 'gui'
        Dir = '01-隐写工具\QrazyBox'; Cmd = 'QrazyBox.bat'
        Desc = '离线二维码分析 / 重建（残缺二维码、掩码、格式位）'
        Usage = @('用默认浏览器打开本地页面，加载二维码图，标记三个定位点后解码。')
        Tips = @('完全离线，比赛断网也能用。')
    },

    # ---------------- 02 取证
    [pscustomobject]@{
        Id = 6; Cat = '取证'; Name = 'Volatility 3'; Kind = 'cli'; Mode = 'file'
        Dir = '02-取证工具\Volatility3'; Cmd = 'vol.bat'
        Desc = '内存取证主力：进程、网络、命令行、注册表、文件'
        Template = '-f "{0}" {1}'; Extra = 'windows.info'
        Usage = @('拖内存镜像进来 -> 默认先跑 windows.info 确认镜像类型',
                  '-f mem.raw windows.pslist    进程列表',
                  '-f mem.raw windows.netscan   网络连接',
                  '-f mem.raw windows.cmdline   进程命令行（找 flag 常用）',
                  '-f mem.raw windows.filescan | findstr flag')
        Tips = @('malfind / handles 这类插件很慢，几分钟正常。',
                 '符号缓存放在 Volatility3\cache，不会污染系统。')
    },
    [pscustomobject]@{
        Id = 7; Cat = '取证'; Name = 'MemProcFS'; Kind = 'cli'; Mode = 'file'
        Dir = '02-取证工具\MemProcFS'; Cmd = 'MemProcFS.bat'
        Desc = '把内存镜像挂成虚拟文件系统，用资源管理器直接翻'
        Template = '"{0}" {1}'; Extra = ''
        Usage = @('拖内存镜像进来 -> 挂载到 MemProcFS\mnt，用资源管理器打开',
                  '-device mem.raw -mount D:\mnt  手动指定挂载点')
        Tips = @('不想背 Volatility 插件名时最快：mnt 下有 files/ registry/ pid/ name/。',
                 '按 Ctrl+C 停止挂载。')
    },
    [pscustomobject]@{
        Id = 8; Cat = '取证'; Name = 'LovelyMem'; Kind = 'gui'
        Dir = '02-取证工具\LovelyMem'; Cmd = 'Lovelymem-V2-2.5.0-windows-x64.exe'
        Desc = '内存取证一体化 GUI（内置 Volatility2，点点鼠标出结果）'
        Usage = @('双击 exe，把内存镜像拖进去，选要跑的分析项。')
        Tips = @('适合快速过一遍；细节还是用 Volatility 3 复核。')
    },
    [pscustomobject]@{
        Id = 9; Cat = '取证'; Name = 'ZipCenOp'; Kind = 'cli'; Mode = 'file'
        Dir = '02-取证工具\ZipCenOp'; Cmd = 'ZipCenOp.bat'
        Desc = 'ZIP 伪加密修复（加密位被置 1 但其实没密码）'
        Template = 'r "{0}" {1}'; Extra = ''
        Usage = @('拖 zip 进来 -> 自动执行 r（恢复伪加密）',
                  'r file.zip  去掉伪加密（会直接改 zip，先备份）',
                  'e file.zip  反向：给 zip 加伪加密（出题用）')
        Tips = @('伪加密特征：zipinfo 显示加密，但解压工具不弹密码框 / 密码随便输也错。')
    },
    [pscustomobject]@{
        Id = 10; Cat = '取证'; Name = 'Hashcat'; Kind = 'cli'; Mode = 'args'
        Dir = '02-取证工具\Hashcat'; Cmd = 'hashcat.bat'
        Desc = '哈希爆破（GPU/CPU），配合 rockyou.txt'
        Template = '{0}'; Extra = ''
        Usage = @('-m 0 -a 0 hashes.txt rockyou.txt   MD5 + 字典',
                  '-m 0 hashes.txt --show            查看已爆破结果',
                  '-m 17200 hashes.txt rockyou.txt   ZIP 伪加密哈希',
                  '-m 1000 hashes.txt rockyou.txt    Windows NTLM',
                  '-b                                先测本机速度')
        Tips = @('运行中按 s 看进度、p 暂停、q 退出。',
                 '字典放 Hashcat 目录下，或写绝对路径。')
    },

    # ---------------- 03 MISC
    [pscustomobject]@{
        Id = 11; Cat = 'MISC'; Name = 'Ciphey'; Kind = 'cli'; Mode = 'text'
        Dir = '03-MISC解题\Ciphey'; Cmd = 'ciphey.bat'
        Desc = '自动识别并解码密文（Base/ROT/摩斯/凯撒… 一把梭）'
        Template = '-t "{0}" {1}'; Extra = ''
        Usage = @('输入密文字符串，它自己猜算法并解出明文',
                  '-t "Uryyb Jbeyq" -v -v   更啰嗦的输出',
                  '-t "..." -c 30           限制破解时间 30 秒')
        Tips = @('输入是文本不是文件；二进制先 strings 再取可疑片段。')
    },
    [pscustomobject]@{
        Id = 12; Cat = 'MISC'; Name = 'CRC32-Tools'; Kind = 'cli'; Mode = 'file'
        Dir = '03-MISC解题\CRC32-Tools'; Cmd = 'CRC32-Tools.bat'
        Desc = 'ZIP CRC32 碰撞爆破（1-4 字节明文）'
        Template = '-z "{0}" {1}'; Extra = ''
        Usage = @('拖 zip 进来 -> 列出每个条目的 CRC32',
                  '-1 / -2 / -3 / -4 file.zip  对应 1~4 字节明文的碰撞爆破',
                  '-z file.zip                 只看 CRC 列表')
        Tips = @('典型题：zip 里有个小文件，已知 CRC 和长度，反推内容。')
    },
    [pscustomobject]@{
        Id = 13; Cat = 'MISC'; Name = 'PNG 尺寸修复'; Kind = 'cli'; Mode = 'file'
        Dir = '03-MISC解题\PNG尺寸修复'; Cmd = 'fixpng.bat'
        Desc = 'PNG 宽高被改坏的自动爆破修复（IHDR 修复）'
        Template = '-i "{0}" {1}'; Extra = ''
        Usage = @('拖残缺 png 进来 -> 自动爆破宽高并导出修复图',
                  '-r 1200x800 broken.png   已知尺寸时直接修')
        Tips = @('特征：图片只显示上半截、或直接报 CRC/IDAT 错误。')
    },
    [pscustomobject]@{
        Id = 14; Cat = 'MISC'; Name = 'Typhon'; Kind = 'cli'; Mode = 'args'
        Dir = '03-MISC解题\Typhon'; Cmd = 'typhon.bat'
        Desc = 'pyjail / 沙箱逃逸 payload 自动生成（带 Web UI）'
        Template = '{0}'; Extra = ''
        Usage = @('webui            启动本地 Web UI（推荐，浏览器里搜 payload）',
                  '--help           看全部命令行参数')
        Tips = @('把题目的 jail 源码 / 黑名单粘进 Web UI，它会搜索可用 payload。')
    },
    [pscustomobject]@{
        Id = 15; Cat = 'MISC'; Name = 'FileReverse-Tools'; Kind = 'cli'; Mode = 'file'
        Dir = '03-MISC解题\FileReverse-Tools'; Cmd = 'FileReverse-Tools.bat'
        Desc = '文件反转 / 双字节倒置 / hex 导出 / unhex'
        Template = '-hh "{0}" {1}'; Extra = ''
        Usage = @('拖文件进来 -> 默认导出 16 进制文本（-hh）',
                  '-uh file.txt     hex 文本还原成文件',
                  '-i  file.bin     按双字节读并倒置',
                  '-r / -re         十六进制倒置 / 双字节反转',
                  '-a / -b          导出 hex 数组 / base64 文本解码')
        Tips = @('也有 GUI 版：FileReverse-Tools_Win_x64_1.02.exe，双击即用。')
    },
    [pscustomobject]@{
        Id = 16; Cat = 'MISC'; Name = 'CTFCrackTools-X'; Kind = 'gui'
        Dir = '03-MISC解题\CTFCrackTools'; Cmd = 'ctfcracktools-x-0.1.2-windows-x64.exe'
        Desc = 'MISC 综合工具箱 GUI（编码、现代密码、杂项）'
        Usage = @('双击 exe 打开，左侧选模块。')
        Tips = @('与 CyberChef 互补：它的「现代密码」模块对 RSA 小脚本更顺手。')
    },

    # ---------------- 04 文件与十六进制
    [pscustomobject]@{
        Id = 17; Cat = '文件/十六进制'; Name = 'binwalk'; Kind = 'cli'; Mode = 'file'
        Dir = '04-文件与十六进制\binwalk'; Cmd = 'binwalk.bat'
        Desc = '文件签名扫描：找隐藏的 png/zip/固件片段、附加数据'
        Template = '"{0}" {1}'; Extra = ''
        Usage = @('拖可疑文件进来 -> 直接签名扫描',
                  '-e file.bin      尝试解包（Windows 支持有限）',
                  '-R "\x89PNG" file.bin   按原始字节搜',
                  '-A file.bin      指令特征扫描')
        Tips = @('拿到 offset 后用 Bandizip / 010 Editor 手动切，比 -e 稳。')
    },

    # ---------------- 05 密码学
    [pscustomobject]@{
        Id = 18; Cat = '密码学'; Name = '密码学库环境'; Kind = 'shell'
        Dir = '05-密码学'; Cmd = '密码学库环境.bat'
        Desc = '开一个已装好 pycryptodome / gmpy2 / z3 的 Python 命令行'
        Usage = @('直接回车即可进入；可在里面写脚本跑 RSA / 约束求解。')
        Tips = @('库在 05-密码学\*\lib，通过 PYTHONPATH 挂载，不污染系统 Python。')
    }
)

$Extras = @(
    [pscustomobject]@{ Id = 90; Cat = '其他'; Name = '工具箱命令行'; Desc = '开一个已配好 ruby/zsteg/密码学库环境的 cmd'; Kind = 'openbat'; Dir = '.'; Cmd = '环境变量.bat' },
    [pscustomobject]@{ Id = 91; Cat = '其他'; Name = '使用方法文档'; Desc = '打开 工具使用方法.md（每个工具怎么用 + 常见报错）'; Kind = 'openfile'; Dir = '.'; Cmd = '工具使用方法.md' },
    [pscustomobject]@{ Id = 92; Cat = '其他'; Name = '打开包目录'; Desc = '在资源管理器里打开本工具包'; Kind = 'opendir'; Dir = '.'; Cmd = '' },
    [pscustomobject]@{ Id = 93; Cat = '其他'; Name = '检查环境'; Desc = '检查 python / java / node / ruby 是否可用'; Kind = 'check'; Dir = '.'; Cmd = '' }
)

# ------------------------------------------------------------------ 显示

function Write-Head {
    Clear-Host
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host '     CTF 杂项补齐包 · 交互菜单        (输入编号或工具名)' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host ("     位置: {0}" -f $Root) -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Menu {
    Write-Head
    $all = @($Tools) + @($Extras)
    $cats = $all | Group-Object Cat
    foreach ($g in $cats) {
        Write-Host ('  -- ' + $g.Name + ' ' + ('-' * (56 - $g.Name.Length))) -ForegroundColor Yellow
        foreach ($t in ($g.Group | Sort-Object Id)) {
            $id = '{0,2}' -f $t.Id
            Write-Host ('   ' + $id + '. ') -NoNewline -ForegroundColor Green
            Write-Host ($t.Name.PadRight(20)) -NoNewline -ForegroundColor White
            Write-Host (' ' + $t.Desc) -ForegroundColor DarkGray
        }
        Write-Host ''
    }
    Write-Host '    0. 退出' -ForegroundColor Green
    Write-Host ''
}

# ------------------------------------------------------------------ 运行

function Split-Args([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    $m = [regex]::Matches($s, '("[^"]*"|\S+)')
    $out = New-Object System.Collections.ArrayList
    foreach ($x in $m) { [void]$out.Add($x.Value.Trim('"')) }
    # 开头的逗号：返回"数组本身"。否则单元素数组会被 PowerShell 拆包成裸字符串，
    # 再用 @splat 传参时字符串会按字符展开，路径被拆成 D、:、\ ...
    return $out.ToArray()
}

function Show-Card($t) {
    Write-Host ''
    Write-Host ('  === ' + $t.Name + ' ===') -ForegroundColor Cyan
    Write-Host ('  用途: ' + $t.Desc)
    if ($t.Usage) {
        Write-Host '  用法:' -ForegroundColor Yellow
        foreach ($u in $t.Usage) { Write-Host ('    ' + $u) }
    }
    if ($t.Tips) {
        Write-Host '  提示:' -ForegroundColor Yellow
        foreach ($u in $t.Tips) { Write-Host ('    ' + $u) -ForegroundColor DarkGray }
    }
    Write-Host ''
}

function Wait-Back {
    Write-Host ''
    Write-Host '  按回车返回菜单...' -ForegroundColor DarkGray -NoNewline
    [void](Read-Host)
}

function Invoke-Tool($t) {
    Write-Head
    Show-Card $t

    $dir = Join-Path $Root $t.Dir
    if (-not (Test-Path $dir)) {
        Write-Host ('  [错误] 目录不存在: ' + $dir) -ForegroundColor Red
        Wait-Back; return
    }

    switch ($t.Kind) {
        'gui' {
            $exe = Join-Path $dir $t.Cmd
            if (-not (Test-Path $exe)) { Write-Host ('  [错误] 找不到: ' + $exe) -ForegroundColor Red; Wait-Back; return }
            Write-Host ('  正在启动 ' + $t.Cmd + ' ...') -ForegroundColor Green
            try {
                if ($t.Cmd -like '*.bat') {
                    Push-Location $dir
                    & $exe
                    Pop-Location
                } else {
                    Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
                }
            } catch {
                Write-Host ('  [错误] 启动失败: ' + $_.Exception.Message) -ForegroundColor Red
            }
            Wait-Back
            return
        }
        { $_ -in 'openbat', 'shell' } {
            $bat = Join-Path $dir $t.Cmd
            if (-not (Test-Path $bat)) { Write-Host ('  [错误] 找不到: ' + $bat) -ForegroundColor Red; Wait-Back; return }
            Write-Host '  正在打开新窗口...' -ForegroundColor Green
            Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('"' + $bat + '"') -WorkingDirectory $dir | Out-Null
            Wait-Back
            return
        }
        'openfile' {
            $f = Join-Path $dir $t.Cmd
            if (-not (Test-Path $f)) { Write-Host ('  [错误] 找不到: ' + $f) -ForegroundColor Red; Wait-Back; return }
            Start-Process -FilePath $f | Out-Null
            Write-Host ('  已用默认程序打开: ' + $f) -ForegroundColor Green
            Wait-Back
            return
        }
        'opendir' {
            Start-Process explorer.exe $Root | Out-Null
            Wait-Back
            return
        }
        'check' {
            Write-Host '  依赖检查:' -ForegroundColor Yellow
            foreach ($c in @('python', 'py', 'java', 'javaw', 'node')) {
                $p = Get-Command $c -ErrorAction SilentlyContinue
                if ($p) {
                    $ver = ''
                    try { $ver = (& $c --version 2>&1 | Select-Object -First 1) } catch {}
                    Write-Host ('    ' + $c.PadRight(8) + ' OK    ' + $p.Source + '   ' + $ver) -ForegroundColor Green
                } else {
                    Write-Host ('    ' + $c.PadRight(8) + ' 缺失（相关工具会报错）') -ForegroundColor Red
                }
            }
            $ruby = Join-Path $Root '01-隐写工具\zsteg\ruby\bin\ruby.exe'
            if (Test-Path $ruby) { Write-Host '    ruby     内置   zsteg\ruby\bin\ruby.exe' -ForegroundColor Green }
            else { Write-Host '    ruby     内置 ruby 缺失' -ForegroundColor Red }
            Write-Host ''
            Write-Host '  说明：python / java 只要有一个版本在 PATH 里就行；工具包自带的不用管。' -ForegroundColor DarkGray
            Wait-Back
            return
        }
    }

    # ---- CLI 工具
    $bat = Join-Path $dir $t.Cmd
    if (-not (Test-Path $bat)) { Write-Host ('  [错误] 找不到: ' + $bat) -ForegroundColor Red; Wait-Back; return }

    $extra = ''
    $callArgs = @()

    switch ($t.Mode) {
        'file' {
            Write-Host '  把要处理的文件直接拖进这个窗口（或粘贴完整路径），回车：' -ForegroundColor Yellow
            Write-Host '    （直接回车 = 只看这个工具自带的帮助）' -ForegroundColor DarkGray
            $f = Read-Host '  文件'
            $f = $f.Trim().Trim('"').Trim("'")
            if ([string]::IsNullOrWhiteSpace($f)) {
                $callArgs = @()
            } elseif (-not (Test-Path $f)) {
                Write-Host ('  [警告] 找不到这个文件: ' + $f) -ForegroundColor Red
                Wait-Back; return
            } else {
                if ([string]::IsNullOrWhiteSpace($t.Extra)) { $extra = '' }
                else {
                    Write-Host ('  附加参数（直接回车用默认: ' + $t.Extra + '）：') -ForegroundColor Yellow
                    $extra = Read-Host '  参数'
                    if ([string]::IsNullOrWhiteSpace($extra)) { $extra = $t.Extra }
                }
                $line = $t.Template -f $f, $extra
                $callArgs = @(Split-Args $line)
            }
        }
        'text' {
            Write-Host '  输入要处理的文本（回车执行，留空看帮助）：' -ForegroundColor Yellow
            $s = Read-Host '  文本'
            if ([string]::IsNullOrWhiteSpace($s)) { $callArgs = @() }
            else { $callArgs = @('-t', $s) }
        }
        'args' {
            Write-Host '  输入参数（回车执行，留空看帮助）：' -ForegroundColor Yellow
            $s = Read-Host '  参数'
            $callArgs = @(Split-Args $s)
        }
        default {
            Write-Host '  输入参数（留空看帮助）：' -ForegroundColor Yellow
            $s = Read-Host '  参数'
            $callArgs = @(Split-Args $s)
        }
    }

    Write-Host ''
    Write-Host ('  ------------------------------------------------------------') -ForegroundColor DarkCyan
    Write-Host ('  执行: ' + $t.Cmd + ' ' + ($callArgs -join ' ')) -ForegroundColor DarkCyan
    Write-Host ('  ------------------------------------------------------------') -ForegroundColor DarkCyan
    Write-Host ''

    Push-Location $dir
    try {
        & $bat @callArgs
        $code = $LASTEXITCODE
    } catch {
        Write-Host ('  [错误] 执行失败: ' + $_.Exception.Message) -ForegroundColor Red
        $code = -1
    } finally {
        Pop-Location
    }

    Write-Host ''
    if ($code -eq 0) { Write-Host ('  [完成] 退出码 ' + $code) -ForegroundColor Green }
    else { Write-Host ('  [注意] 退出码 ' + $code + '（非 0 通常是参数没给对，看上面的提示）') -ForegroundColor Yellow }
    Wait-Back
}

# ------------------------------------------------------------------ 主循环

# 自检模式：只渲染一次菜单就退出（用于验证脚本可用）
if ($args -contains '-selftest') { Show-Menu; exit 0 }

while ($true) {
    Show-Menu
    $choice = Read-Host '  请输入编号（回车刷新，q 退出）'
    if ([string]::IsNullOrWhiteSpace($choice)) { continue }
    $choice = $choice.Trim()
    if ($choice -in @('q', 'Q', 'quit', 'exit', '0')) { break }

    $all = @($Tools) + @($Extras)
    $hit = $null
    $num = 0
    if ([int]::TryParse($choice, [ref]$num)) {
        $hit = $all | Where-Object { $_.Id -eq $num } | Select-Object -First 1
    }
    if (-not $hit) {
        $hit = $all | Where-Object { $_.Name -eq $choice } | Select-Object -First 1
    }
    if (-not $hit) {
        $hit = $all | Where-Object { $_.Name -like ('*' + $choice + '*') } | Select-Object -First 1
    }
    if (-not $hit) {
        Write-Host ''
        Write-Host ('  没有这个编号/名字: ' + $choice) -ForegroundColor Red
        Start-Sleep -Milliseconds 900
        continue
    }
    Invoke-Tool $hit
}

Clear-Host
Write-Host ''
Write-Host '  已退出。下次双击 启动菜单.bat 即可。' -ForegroundColor Cyan
Write-Host ''
