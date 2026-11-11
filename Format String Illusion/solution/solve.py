#!/usr/bin/env python3
from pathlib import Path
import tempfile,shutil,subprocess,sys
HERE=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="ctf-text-") as td:
    work=Path(td)
    shutil.copytree(HERE.parent/"challenge",work,dirs_exist_ok=True)
    shutil.copy2(HERE/"solution.py",work/"solution.py")
    raise SystemExit(subprocess.run([sys.executable,str(work/"solution.py")],cwd=work).returncode)
