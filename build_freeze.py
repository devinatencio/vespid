#!/usr/bin/env python3
"""Build a single cx_Freeze target. Called by build_freeze.sh.

Usage: build_freeze.py <target>
  target: vespid, vespid-cli, vespid-server
"""
import shutil
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
OUT = SRC / "dist" / "freeze"

TARGET = sys.argv[1] if len(sys.argv) > 1 else ""
assert TARGET, "Usage: build_freeze.py <target>"

PYTHON = SRC / ".build-venv" / "bin" / "python3"


def write_and_run(name: str, content: str) -> None:
    script = OUT / f"_{name}_setup.py"
    script.write_text(content)
    r = subprocess.run(
        [str(PYTHON), str(script), "build_exe"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(r.returncode)


if TARGET == "vespid":
    target_dir = OUT / "vespid"
    if target_dir.exists():
        shutil.rmtree(target_dir)
    write_and_run("vespid", f"""
import sys
sys.path.insert(0, '{SRC}')
from cx_Freeze import setup, Executable
setup(
    name='vespid',
    version='1.0.1',
    options={{
        'build_exe': {{
            'build_exe': '{target_dir}',
            'packages': ['vespid'],
            'excludes': ['tkinter', 'pytest', 'test', 'unittest'],
            'include_files': [
                ('{SRC / "data"}', 'lib/data'),
            ],
            'optimize': 2,
        }}
    }},
    executables=[Executable('{SRC / "entry_vespid.py"}', target_name='vespid')],
)
""")

elif TARGET == "vespid-cli":
    target_dir = OUT / "vespid-cli"
    if target_dir.exists():
        shutil.rmtree(target_dir)
    write_and_run("vespid-cli", f"""
import sys
sys.path.insert(0, '{SRC}')
from cx_Freeze import setup, Executable
setup(
    name='vespid-cli',
    version='1.0.1',
    options={{
        'build_exe': {{
            'build_exe': '{target_dir}',
            'packages': ['vespid'],
            'excludes': ['tkinter', 'pytest', 'test', 'unittest'],
            'include_files': [
                ('{SRC / "data"}', 'lib/data'),
            ],
            'optimize': 2,
        }}
    }},
    executables=[Executable('{SRC / "entry_vespid_cli.py"}', target_name='vespid-cli')],
)
""")

elif TARGET == "vespid-server":
    target_dir = OUT / "vespid-server"
    if target_dir.exists():
        shutil.rmtree(target_dir)
    write_and_run("vespid-server", f"""
import sys
sys.path.insert(0, '{SRC / "vespid-server"}')
from cx_Freeze import setup, Executable
setup(
    name='vespid-server',
    version='1.0.1',
    options={{
        'build_exe': {{
            'build_exe': '{target_dir}',
            'packages': ['app'],
            'excludes': ['tkinter', 'pytest', 'test', 'unittest', 'gunicorn'],
            'include_files': [
                ('{SRC / "vespid-server/app/templates"}', 'app/templates'),
                ('{SRC / "vespid-server/app/static"}', 'app/static'),
                ('{SRC / "data"}', 'lib/data'),
            ],
            'optimize': 2,
        }}
    }},
    executables=[
        Executable('{SRC / "entry_vespid_server.py"}', target_name='vespid-server'),
    ],
)
""")

else:
    print(f"Unknown target: {TARGET}")
    sys.exit(1)

print(f"[OK] {TARGET} built → {target_dir}")
