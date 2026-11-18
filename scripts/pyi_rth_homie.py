# scripts/pyi_rth_homie.py - PyInstaller Runtime Hook for Homie
"""Executes at PyInstaller bootstrap before user scripts are loaded.
Prepares sys.path, environment variables, and Windows UTF-8 console output.
"""
import sys
import os

# Set standalone marker
os.environ["HOMIE_STANDALONE"] = "1"

if getattr(sys, "frozen", False):
    bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    exe_dir = os.path.dirname(sys.executable)

    os.environ["HOMIE_BUNDLE_DIR"] = bundle_dir
    os.environ["HOMIE_APP_DIR"] = exe_dir

    for directory in (bundle_dir, exe_dir):
        if directory and directory not in sys.path:
            sys.path.insert(0, directory)

    # Reconfigure streams to avoid utf-8 decode/encode errors in Windows consoles
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
