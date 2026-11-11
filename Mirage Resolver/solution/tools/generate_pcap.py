"""PCAP generator entrypoint for Mirage Resolver."""

from __future__ import annotations

import argparse
from pathlib import Path

from challenge_config import DEFAULT_PCAP_NAME, FLAG, ROOT_DIR_NAME, SEED_DEFAULT
from publish_dns_stream import build_generation_plan, write_pcap


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Mirage Resolver PCAP")
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
    print(
        "[plan] "
        f"seed={args.seed} packets={counts.total_packets} pairs={counts.total_pairs} encoded_bytes={counts.encoded_bytes}"
    )
    print(
        "[plan] "
        f"signal_pairs={counts.signal_pairs} noise_a_pairs={counts.noise_a_pairs} "
        f"noise_txt_pairs={counts.noise_txt_pairs} noise_nxdomain_pairs={counts.noise_nxdomain_pairs}"
    )
    print(f"[plan] decoy_flag_messages={counts.decoy_flag_messages}")

    if args.dry_run:
        print("[dry-run] generation plan built, no file emitted")
        return 0

    write_pcap(plans, output_path=output_path)
    print(f"[done] wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
