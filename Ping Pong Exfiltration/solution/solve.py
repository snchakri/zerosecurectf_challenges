#!/usr/bin/env python3
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHALLENGE=HERE.parent/"challenge"
import subprocess,sys,tempfile
capture=next(CHALLENGE.glob("*.pcap"))
with tempfile.TemporaryDirectory(prefix="ctf-network-") as td:
    command=[sys.executable,str(HERE/"tools/solve_reference.py"),"--pcap",str(capture)]
    command += ["--output-zip",str(Path(td)/"recovered.zip")]
    raise SystemExit(subprocess.run(command).returncode)

