# main.py
"""
Janus - BOLA/IDOR Vulnerability Scanner
Entry point for CLI and Web interfaces.
"""

import sys
import os

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(__file__))

from janus.interface.cli import app, main

if __name__ == "__main__":
    main()
