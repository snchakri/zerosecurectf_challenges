"""Strict flag validator for Knock-Knock Joke."""

from __future__ import annotations

import argparse
import re

from challenge_config import FLAG

STRICT_RE = re.compile(r"^ZeroSecure_CTF\{.+\}$")


def validate(candidate: str) -> tuple[bool, str]:
    if not STRICT_RE.match(candidate):
        return False, "Invalid format. Expected ZeroSecure_CTF{...}"
    if candidate != FLAG:
        return False, "Incorrect flag"
    return True, "Correct"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate submitted flag")
    parser.add_argument("flag", help="Candidate flag string")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    ok, message = validate(args.flag.strip())
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
