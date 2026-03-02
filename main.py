#!/usr/bin/env python3
# main.py — convenience entry point for development
# For production use: python -m netscope   OR   netscope (after pip install)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netscope.cli import main
if __name__ == "__main__":
    main()