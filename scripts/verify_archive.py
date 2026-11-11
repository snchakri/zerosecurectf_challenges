#!/usr/bin/env python3
"""Check the archive manifest, two-folder layout, and complete file hashes."""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
def verify():
    errors=[]
    manifest=json.loads((ROOT/"manifest.json").read_text(encoding="utf-8"))
    folders=[r["folder"] for r in manifest["challenges"]]
    if len(set(folders))!=len(folders):errors.append("Duplicate challenge folders")
    for folder in folders:
        p=ROOT/folder
        if not p.is_dir():errors.append("Missing challenge: "+folder);continue
        if {x.name for x in p.iterdir()}!={"challenge","solution"}:errors.append("Unexpected layout: "+folder)
        for sub in ["challenge","solution"]:
            if not (p/sub/"README.md").is_file():errors.append("Missing README: "+folder+"/"+sub)
    expected={}
    for line in (ROOT/"SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest,name=line.split("  ",1);expected[name]=digest
        p=ROOT/name
        if not p.is_file():errors.append("Missing file: "+name)
        elif hashlib.sha256(p.read_bytes()).hexdigest()!=digest:errors.append("Changed file: "+name)
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.relative_to(ROOT).parts and "__pycache__" not in p.parts and p.name!="SHA256SUMS" and (not p.name.endswith(".pyc") or p.name=="palimpsest.pyc")}
    for name in sorted(actual-set(expected)):errors.append("Unlisted file: "+name)
    for name in sorted(set(expected)-actual):errors.append("Absent inventory file: "+name)
    if errors:
        for error in errors:print(error,file=sys.stderr)
        return 1
    print(f"Verified {len(folders)} challenge folders and {len(expected)} file hashes.")
    return 0
if __name__=="__main__":raise SystemExit(verify())
