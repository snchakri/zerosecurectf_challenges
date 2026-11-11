"""PCAP generator entrypoint for Knock-Knock Joke."""

from __future__ import annotations

import argparse
from pathlib import Path

from challenge_config import DEFAULT_PCAP_NAME, FLAG, ROOT_DIR_NAME, SEED_DEFAULT
from publish_tcp_knock_stream import build_generation_plan, write_pcap


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Knock-Knock Joke PCAP")
    parser.add_argument("--seed", type=int, default=SEED_DEFAULT, help="Deterministic random seed")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables" / DEFAULT_PCAP_NAME,
        help="Output PCAP path",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print plan statistics without writing a PCAP")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    output_path = args.output.resolve()

    plans, counts = build_generation_plan(seed=args.seed, flag_text=FLAG)

    print(f"[challenge] {ROOT_DIR_NAME}")
    print(f"[plan] seed={args.seed} packets={counts.total_packets} flag_chars={len(FLAG)}")
    print(
        "[plan] "
        f"signal_syn={counts.signal_syn_packets} signal_rst={counts.signal_rst_packets} "
        f"noise={counts.noise_packets}"
    )
    print(f"[plan] noise_tcp={counts.noise_tcp_packets} noise_udp={counts.noise_udp_packets}")

    if args.dry_run:
        print("[dry-run] generation plan built, no file emitted")
        return 0

    write_pcap(plans, output_path=output_path)
    print(f"[done] wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
