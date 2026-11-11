#!/usr/bin/env python3
"""Validate and push this prepared archive; never force-push or store credentials."""
from pathlib import Path
import argparse,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1]
def command(args,check=True):
    result=subprocess.run(args,cwd=ROOT,check=False)
    if check and result.returncode:raise SystemExit(result.returncode)
    return result.returncode
def publish(args):
    command([sys.executable,str(ROOT/"scripts/verify_archive.py")])
    if args.check:return
    branch=subprocess.check_output(["git","branch","--show-current"],cwd=ROOT,text=True).strip()
    if branch!="main":raise SystemExit("Switch to the prepared main branch before publishing.")
    if args.commit:
        command(["git","add","--all"])
        if command(["git","diff","--cached","--quiet"],check=False):
            command(["git","commit","-m",args.message])
    command(["git","push","origin","main"])
    print("Published main to origin.")
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check",action="store_true",help="Validate only; do not commit or push")
    ap.add_argument("--commit",action="store_true",help="Commit the validated local archive before pushing")
    ap.add_argument("--message",default="Complete local ZeroSecureCTF challenge archive")
    ap.add_argument("--watch",type=int,metavar="SECONDS",help="Repeat validation and publishing until interrupted")
    args=ap.parse_args()
    if args.watch is not None and args.watch<10:ap.error("--watch must be at least 10 seconds")
    while True:
        publish(args)
        if args.watch is None:return
        time.sleep(args.watch)
if __name__=="__main__":main()
