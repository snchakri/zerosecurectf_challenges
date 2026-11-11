"""Live-capture orchestrator for Rogue Edge Sensor challenge PCAP generation."""

from __future__ import annotations

import argparse
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from challenge_config import (
    BROKER_HOST,
    BROKER_PORT,
    DEFAULT_PCAP_NAME,
    ROOT_DIR_NAME,
    SEED_DEFAULT,
)
from publish_telemetry import build_generation_plan, publish_plan


def _find_command(command: str) -> str:
    resolved = shutil.which(command)
    if not resolved:
        raise FileNotFoundError(f"Required command not found in PATH: {command}")
    return resolved


def _list_tshark_interfaces(tshark_bin: str) -> list[str]:
    result = subprocess.run([tshark_bin, "-D"], check=True, capture_output=True, text=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _autodetect_interface(tshark_bin: str) -> str:
    interfaces = _list_tshark_interfaces(tshark_bin)
    preferred_tokens = ("loopback", "npcap", "adapter for loopback", "lo")
    for line in interfaces:
        lower = line.lower()
        if any(token in lower for token in preferred_tokens):
            # tshark -D lines are commonly like: "1. \Device\NPF_Loopback (... )"
            dot_index = line.find(".")
            if dot_index > 0:
                return line[:dot_index]
            return line
    # Fallback to first interface entry.
    if not interfaces:
        raise RuntimeError("No capture interfaces returned by tshark -D")
    first = interfaces[0]
    dot_index = first.find(".")
    return first[:dot_index] if dot_index > 0 else first


def _terminate_process(proc: subprocess.Popen[bytes] | subprocess.Popen[str], name: str) -> None:
    if proc.poll() is not None:
        return

    try:
        if sys.platform == "win32":
            proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[arg-type]
            time.sleep(0.6)
        else:
            proc.terminate()
            time.sleep(0.6)
    except Exception:
        pass

    if proc.poll() is None:
        proc.terminate()
        time.sleep(0.6)

    if proc.poll() is None:
        proc.kill()


def _start_broker(mosquitto_bin: str, port: int) -> subprocess.Popen[str]:
    cmd = [mosquitto_bin, "-p", str(port), "-v"]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _start_capture(tshark_bin: str, interface: str, output_pcap: Path, port: int) -> subprocess.Popen[str]:
    cmd = [
        tshark_bin,
        "-i",
        interface,
        "-f",
        f"tcp port {port}",
        "-w",
        str(output_pcap),
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Rogue Edge Sensor PCAP using live capture")
    parser.add_argument("--seed", type=int, default=SEED_DEFAULT, help="Deterministic random seed")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables" / DEFAULT_PCAP_NAME,
        help="Output PCAP path",
    )
    parser.add_argument("--broker-host", default=BROKER_HOST, help="MQTT broker host")
    parser.add_argument("--broker-port", type=int, default=BROKER_PORT, help="MQTT broker port")
    parser.add_argument("--interface", default="auto", help="Capture interface index/name, or 'auto'")
    parser.add_argument("--time-scale", type=float, default=1.0, help="Playback speed multiplier")
    parser.add_argument("--mosquitto-bin", default="mosquitto", help="Mosquitto binary path")
    parser.add_argument("--tshark-bin", default="tshark", help="tshark binary path")
    parser.add_argument("--dry-run", action="store_true", help="Skip broker/capture and only materialize schedule")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    output_pcap: Path = args.output.resolve()
    output_pcap.parent.mkdir(parents=True, exist_ok=True)

    messages, counts = build_generation_plan(seed=args.seed)
    print(
        f"[plan] total={counts.total} signal={counts.signal} decoy_a={counts.decoy_a} decoy_b={counts.decoy_b} "
        f"seed={args.seed}"
    )

    if args.dry_run:
        print("[dry-run] Schedule generated only, capture/publish skipped")
        return 0

    mosquitto_bin = _find_command(args.mosquitto_bin)
    tshark_bin = _find_command(args.tshark_bin)

    interface = args.interface
    if interface == "auto":
        interface = _autodetect_interface(tshark_bin)

    print(f"[capture] interface={interface} output={output_pcap}")

    broker_proc = _start_broker(mosquitto_bin, args.broker_port)
    capture_proc = None

    try:
        # Allow broker startup before capture/publish.
        time.sleep(1.0)

        capture_proc = _start_capture(tshark_bin, interface, output_pcap, args.broker_port)
        # Give tshark time to bind interface before publishing.
        time.sleep(1.0)

        publish_plan(
            messages=messages,
            host=args.broker_host,
            port=args.broker_port,
            time_scale=args.time_scale,
            dry_run=False,
        )

        # Capture trailing ACK/teardown packets.
        time.sleep(1.0)
        print(f"[done] PCAP generated at {output_pcap}")
        return 0
    finally:
        if capture_proc is not None:
            _terminate_process(capture_proc, "tshark")
        _terminate_process(broker_proc, "mosquitto")


if __name__ == "__main__":
    raise SystemExit(main())
