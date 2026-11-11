#!/usr/bin/env python3
import argparse
import os
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path

TRUE_FLAG = "zerosecurectf{caught_final_void}"


def extract_vo_seed(gz_path: Path) -> bytes:
    data = gz_path.read_bytes()
    if data[0] != 0x1F or data[1] != 0x8B:
        raise ValueError("not gzip")

    flg = data[3]
    if (flg & 0x04) == 0:
        raise ValueError("FEXTRA missing")

    pos = 10
    xlen = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    end = pos + xlen

    while pos + 4 <= end:
        si = data[pos:pos + 2]
        slen = struct.unpack_from("<H", data, pos + 2)[0]
        payload = data[pos + 4:pos + 4 + slen]
        if si == b"VO":
            if len(payload) != 48:
                raise ValueError("VO payload must be 48 bytes")
            return payload[:32]
        pos += 4 + slen

    raise ValueError("VO seed subfield not found")


def run_solver(artifact_path: Path) -> str:
    seed = extract_vo_seed(artifact_path)
    seed_hex = seed.hex()

    with tempfile.TemporaryDirectory(prefix="vessel_solve_") as tmp:
        tmp_path = Path(tmp)

        with tarfile.open(artifact_path, "r:gz") as tf:
            tf.extractall(tmp_path)

        bin_path = tmp_path / "void"
        os.chmod(bin_path, 0o755)

        result = subprocess.run(
            [str(bin_path), "mirror", "--seed", seed_hex],
            capture_output=True,
            text=True,
            check=False,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if stdout:
            print(stdout)
        if stderr:
            print(stderr)

        if TRUE_FLAG not in stdout:
            raise RuntimeError("true flag not recovered")

        return TRUE_FLAG


def main():
    parser = argparse.ArgumentParser(description="Reference solver for Vessel of the Void")
    parser.add_argument("--artifact", default="challenge/vessel.tar.gz", help="Path to vessel.tar.gz")
    args = parser.parse_args()

    artifact = Path(args.artifact)
    flag = run_solver(artifact)
    print("[solve] recovered:", flag)


if __name__ == "__main__":
    main()
