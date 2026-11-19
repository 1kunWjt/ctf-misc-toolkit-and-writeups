# -*- coding: utf-8 -*-
"""volatility3 命令行入口（pip --target 装出来的 exe 不可直接跑，用这个）。"""
import sys
from volatility3.cli import main

if __name__ == "__main__":
    sys.argv[0] = "vol"
    sys.exit(main())
