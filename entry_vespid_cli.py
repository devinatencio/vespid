"""Entry point wrapper for Nuitka / cx_Freeze compilation — vespid-cli."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vespid.cli import main

if __name__ == "__main__":
    sys.exit(main())
