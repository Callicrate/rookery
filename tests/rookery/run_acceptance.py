#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

repository_root = Path(__file__).resolve().parents[2]
rookery_root = repository_root / "rookery"
env = dict(os.environ)
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["PYTHONPATH"] = str(rookery_root / "lib") + ((":" + env["PYTHONPATH"]) if env.get("PYTHONPATH") else "")
cmd = [
    sys.executable,
    "-m",
    "unittest",
    "discover",
    "-v",
    "-s",
    "tests/rookery",
    "-p",
    "test_*.py",
    "-t",
    ".",
]
raise SystemExit(subprocess.call(cmd, cwd=repository_root, env=env))
