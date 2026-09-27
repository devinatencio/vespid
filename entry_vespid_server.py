"""Entry point wrapper for Nuitka compilation — vespid-server."""
import sys
import os

# Ensure the vespid-server directory is on the path so 'app' package resolves
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "vespid-server"))

from vespid_server import main

if __name__ == "__main__":
    main()
