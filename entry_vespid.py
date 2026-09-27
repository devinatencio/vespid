"""Entry point wrapper for Nuitka / cx_Freeze compilation — vespid daemon."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vespid.daemon import main

if __name__ == "__main__":
    main()
