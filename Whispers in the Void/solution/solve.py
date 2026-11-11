#!/usr/bin/env python3
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHALLENGE=HERE.parent/"challenge"
import importlib.util
path=HERE/"scripts/noob_participant_solve.py"
spec=importlib.util.spec_from_file_location("whispers_reference",path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.solve(str(CHALLENGE/"whispers_in_the_void.pcap"))

