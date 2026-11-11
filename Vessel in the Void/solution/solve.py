#!/usr/bin/env python3
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHALLENGE=HERE.parent/"challenge"
import subprocess,sys
raise SystemExit(subprocess.run([sys.executable,str(HERE/"author_solver.py"),"--artifact",str(CHALLENGE/"vessel.tar.gz")]).returncode)

