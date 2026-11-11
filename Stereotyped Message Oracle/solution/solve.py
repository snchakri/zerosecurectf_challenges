#!/usr/bin/env python3
"""Execute the reference attack against a temporary copy of the handout."""
from pathlib import Path
import shutil, subprocess, sys, tempfile
HERE = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="ctf-solve-") as td:
    work = Path(td)
    shutil.copytree(HERE.parent / "challenge", work, dirs_exist_ok=True)
    if (HERE / "runtime").exists():
        shutil.copytree(HERE / "runtime", work, dirs_exist_ok=True)
    (work / "dist").mkdir()
    for name in ['stereotyped_rsa.json']:
        shutil.copy2(HERE.parent / "challenge" / name, work / "dist" / name)
    shutil.copy2(HERE / "algorithm.py", work / "algorithm.py")
    result = subprocess.run([sys.executable, str(work / "algorithm.py"), "--dist", "./dist", *sys.argv[1:]], cwd=work)
    raise SystemExit(result.returncode)
