from __future__ import annotations

import argparse
from pathlib import Path


def extract(dataset_path: Path, out_db_path: Path) -> None:
    raw = dataset_path.read_bytes()
    marker = b"\n[VOIDMIND::SQLITE_APPEND_V1]\n"
    idx = raw.find(marker)
    if idx == -1:
        raise RuntimeError("marker not found")

    len_pos = idx + len(marker)
    if len_pos + 8 > len(raw):
        raise RuntimeError("invalid marker framing")

    payload_pos = len_pos + 8
    payload = raw[payload_pos:]
    if not payload.startswith(b"SQLite format 3"):
        raise RuntimeError("appended payload is not sqlite header")

    out_db_path.parent.mkdir(parents=True, exist_ok=True)
    out_db_path.write_bytes(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract appended SQLite payload from void_dataset.npz")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("out_db", type=Path)
    args = parser.parse_args()

    extract(args.dataset, args.out_db)
    print(f"[ok] extracted sqlite payload -> {args.out_db}")


if __name__ == "__main__":
    main()
