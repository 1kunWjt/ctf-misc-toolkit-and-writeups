# -*- coding: utf-8 -*-
"""Typhon (pyjail 自动化解题) 命令行入口。"""
import sys
from Typhon.cli import main

if __name__ == "__main__":
    sys.argv[0] = "typhonbreaker"
    sys.exit(main())
