#!/usr/bin/env python3
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHALLENGE=HERE.parent/"challenge"
import subprocess,sys,tempfile,shutil
with tempfile.TemporaryDirectory(prefix="ctf-reference-") as td:
    work=Path(td)
    shutil.copytree(HERE/"organizer_only",work/"organizer_only")
    shutil.copytree(CHALLENGE,work/"contestant_package")
    command=[sys.executable,str(work/"organizer_only/solve.py")]
    command.append(str(work/"contestant_package"/'transmission.null'))
    result=subprocess.run(command,cwd=work/"contestant_package")
    raise SystemExit(result.returncode)

