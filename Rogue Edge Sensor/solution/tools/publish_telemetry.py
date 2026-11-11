"""Deterministic telemetry plan builder and MQTT publisher for Rogue Edge Sensor."""

from __future__ import annotations

import argparse
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt

from challenge_config import (
    BASE_INTERVAL_MAX,
    BASE_INTERVAL_MIN,
    BROKER_HOST,
    BROKER_PORT,
    CAPTURE_SECONDS,
    DECOY_A_DUPLICATE_PROBABILITY,
    DEFAULT_PCAP_NAME,
    DUPLICATE_OFFSET_SECONDS,
    FLAG,
    HUMIDITY_BOUNDS,
    HUMIDITY_STEP_CHOICES,
    INTERVAL_MAX,
    INTERVAL_MIN,
    JITTER_MAX,
    JITTER_MIN,
    ROOT_DIR_NAME,
    SEED_DEFAULT,
    SIGNAL_ACTIVE_WINDOWS,
    SIGNAL_COUNT_MAX,
    SIGNAL_COUNT_MIN,
    TEMP_MAX,
    TEMP_MIN,
    TEMP_START,
    TEMP_STEP_CHOICES,
    TOPIC_DECOY_A,
    TOPIC_DECOY_B,
    TOPIC_SIGNAL,
    TOTAL_PUBLISH_MAX,
    TOTAL_PUBLISH_MIN,
    TopicCounts,
)


@dataclass
class TelemetryMessage:
    """One scheduled publish operation."""

    timestamp: float
    topic: str
    payload: dict[str, Any]


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def sample_interval(rng: random.Random) -> float:
    """Locked interval model from the plan."""
    base = rng.uniform(BASE_INTERVAL_MIN, BASE_INTERVAL_MAX)
    jitter = rng.uniform(JITTER_MIN, JITTER_MAX)
    return clamp(base + jitter, INTERVAL_MIN, INTERVAL_MAX)


def _generate_ticks_for_window(
    rng: random.Random,
    start_s: float,
    end_s: float,
    initial_phase: float = 0.2,
) -> list[float]:
    ticks: list[float] = []
    t = start_s + rng.uniform(initial_phase, 0.9)
    while t <= end_s:
        ticks.append(round(t, 3))
        t += sample_interval(rng)
    return ticks


def _generate_signal_ticks(rng: random.Random) -> list[float]:
    ticks: list[float] = []
    for start_s, end_s in SIGNAL_ACTIVE_WINDOWS:
        ticks.extend(_generate_ticks_for_window(rng, start_s, end_s))
    ticks.sort()

    # Ensure signal topic sits in locked count band.
    while len(ticks) < SIGNAL_COUNT_MIN:
        ticks.append(round(rng.uniform(SIGNAL_ACTIVE_WINDOWS[0][0], SIGNAL_ACTIVE_WINDOWS[-1][1]), 3))
    if len(ticks) > SIGNAL_COUNT_MAX:
        ticks = ticks[:SIGNAL_COUNT_MAX]

    ticks.sort()
    return ticks


def _generate_decoy_a_ticks(rng: random.Random) -> list[float]:
    base_ticks = _generate_ticks_for_window(rng, 0.0, CAPTURE_SECONDS - 2.0, initial_phase=0.1)
    ticks = list(base_ticks)
    for t in base_ticks:
        if rng.random() < DECOY_A_DUPLICATE_PROBABILITY and t + DUPLICATE_OFFSET_SECONDS < CAPTURE_SECONDS:
            ticks.append(round(t + DUPLICATE_OFFSET_SECONDS, 3))
    ticks.sort()
    return ticks


def _generate_decoy_b_ticks(rng: random.Random) -> list[float]:
    ticks = _generate_ticks_for_window(rng, 0.0, CAPTURE_SECONDS - 2.0, initial_phase=0.4)
    ticks.sort()
    return ticks


def materialize_counts(signal_ticks: list[float], decoy_a_ticks: list[float], decoy_b_ticks: list[float]) -> TopicCounts:
    total = len(signal_ticks) + len(decoy_a_ticks) + len(decoy_b_ticks)
    return TopicCounts(
        total=total,
        signal=len(signal_ticks),
        decoy_a=len(decoy_a_ticks),
        decoy_b=len(decoy_b_ticks),
    )


def _walk_temperature(rng: random.Random, value: float) -> float:
    step = rng.choice(TEMP_STEP_CHOICES)
    return round(clamp(value + step, TEMP_MIN, TEMP_MAX), 1)


def _walk_humidity(rng: random.Random, topic: str, value: int) -> int:
    low, high = HUMIDITY_BOUNDS[topic]
    step = rng.choice(HUMIDITY_STEP_CHOICES)
    return int(clamp(value + step, low, high))


def _format_sensor_raw(temp_value: float, ascii_code: int) -> str:
    # Preserve fixed precision and trailing zeros for solver safety.
    return f"{int(temp_value):02d}.{ascii_code:03d}"


def _build_payload(
    topic: str,
    seq: int,
    temp_value: float,
    humidity_value: int,
    sensor_raw_code: int,
) -> dict[str, Any]:
    sensor_name = topic.split("/")[-1]
    return {
        "sensor_id": sensor_name,
        "seq": seq,
        "temp": temp_value,
        "sensor_raw": _format_sensor_raw(temp_value, sensor_raw_code),
        "humidity": humidity_value,
        "battery": 96,
    }


def build_generation_plan(
    seed: int = SEED_DEFAULT,
    flag_text: str = FLAG,
) -> tuple[list[TelemetryMessage], TopicCounts]:
    """Create a deterministic publish schedule and payload set."""
    rng = random.Random(seed)

    signal_ticks = _generate_signal_ticks(rng)
    decoy_a_ticks = _generate_decoy_a_ticks(rng)
    decoy_b_ticks = _generate_decoy_b_ticks(rng)

    counts = materialize_counts(signal_ticks, decoy_a_ticks, decoy_b_ticks)
    if counts.total < TOTAL_PUBLISH_MIN or counts.total > TOTAL_PUBLISH_MAX:
        raise ValueError(
            f"Total publishes out of bounds: {counts.total} (expected {TOTAL_PUBLISH_MIN}-{TOTAL_PUBLISH_MAX})"
        )

    if counts.signal < len(flag_text):
        raise ValueError(
            f"Signal topic has only {counts.signal} packets, needs at least {len(flag_text)} for the flag"
        )

    # Keep the encoded flag contiguous in signal-topic order so extraction is deterministic,
    # while still leaving trailing signal-topic decoys in the stream.
    signal_message_indices = list(range(len(flag_text)))
    signal_index_to_char = {idx: flag_text[pos] for pos, idx in enumerate(signal_message_indices)}

    # Initialize per-topic state.
    state_temp: dict[str, float] = {
        TOPIC_SIGNAL: TEMP_START,
        TOPIC_DECOY_A: TEMP_START + 0.3,
        TOPIC_DECOY_B: TEMP_START - 0.2,
    }
    state_humidity: dict[str, int] = {
        topic: int((bounds[0] + bounds[1]) / 2) for topic, bounds in HUMIDITY_BOUNDS.items()
    }

    messages: list[TelemetryMessage] = []

    for seq, t in enumerate(signal_ticks):
        state_temp[TOPIC_SIGNAL] = _walk_temperature(rng, state_temp[TOPIC_SIGNAL])
        state_humidity[TOPIC_SIGNAL] = _walk_humidity(rng, TOPIC_SIGNAL, state_humidity[TOPIC_SIGNAL])

        if seq in signal_index_to_char:
            code = ord(signal_index_to_char[seq])
        else:
            code = rng.randint(0, 999)

        payload = _build_payload(
            topic=TOPIC_SIGNAL,
            seq=seq,
            temp_value=state_temp[TOPIC_SIGNAL],
            humidity_value=state_humidity[TOPIC_SIGNAL],
            sensor_raw_code=code,
        )
        messages.append(TelemetryMessage(timestamp=t, topic=TOPIC_SIGNAL, payload=payload))

    for seq, t in enumerate(decoy_a_ticks):
        state_temp[TOPIC_DECOY_A] = _walk_temperature(rng, state_temp[TOPIC_DECOY_A])
        state_humidity[TOPIC_DECOY_A] = _walk_humidity(rng, TOPIC_DECOY_A, state_humidity[TOPIC_DECOY_A])
        code = rng.randint(0, 999)
        payload = _build_payload(
            topic=TOPIC_DECOY_A,
            seq=seq,
            temp_value=state_temp[TOPIC_DECOY_A],
            humidity_value=state_humidity[TOPIC_DECOY_A],
            sensor_raw_code=code,
        )
        messages.append(TelemetryMessage(timestamp=t, topic=TOPIC_DECOY_A, payload=payload))

    for seq, t in enumerate(decoy_b_ticks):
        state_temp[TOPIC_DECOY_B] = _walk_temperature(rng, state_temp[TOPIC_DECOY_B])
        state_humidity[TOPIC_DECOY_B] = _walk_humidity(rng, TOPIC_DECOY_B, state_humidity[TOPIC_DECOY_B])
        code = rng.randint(0, 999)
        payload = _build_payload(
            topic=TOPIC_DECOY_B,
            seq=seq,
            temp_value=state_temp[TOPIC_DECOY_B],
            humidity_value=state_humidity[TOPIC_DECOY_B],
            sensor_raw_code=code,
        )
        messages.append(TelemetryMessage(timestamp=t, topic=TOPIC_DECOY_B, payload=payload))

    messages.sort(key=lambda msg: (msg.timestamp, msg.topic, msg.payload.get("seq", 0)))
    return messages, counts


def publish_plan(
    messages: list[TelemetryMessage],
    host: str = BROKER_HOST,
    port: int = BROKER_PORT,
    time_scale: float = 1.0,
    dry_run: bool = False,
) -> None:
    """Publish messages with timing preserved from scheduled timestamps."""
    if dry_run:
        return

    client = mqtt.Client(client_id=f"{ROOT_DIR_NAME}-publisher", protocol=mqtt.MQTTv311)
    client.connect(host, port, keepalive=60)
    client.loop_start()

    start_wall = time.monotonic()
    first_ts = messages[0].timestamp if messages else 0.0

    try:
        for msg in messages:
            scheduled = (msg.timestamp - first_ts) * max(time_scale, 0.001)
            while True:
                now = time.monotonic() - start_wall
                remaining = scheduled - now
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.05))

            payload_text = json.dumps(msg.payload, separators=(",", ":"))
            client.publish(msg.topic, payload_text, qos=0, retain=False)
    finally:
        client.loop_stop()
        client.disconnect()


def export_plan_json(messages: list[TelemetryMessage], path: Path) -> None:
    materialized = [
        {
            "timestamp": msg.timestamp,
            "topic": msg.topic,
            "payload": msg.payload,
        }
        for msg in messages
    ]
    path.write_text(json.dumps(materialized, indent=2), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and optionally publish telemetry plan")
    parser.add_argument("--seed", type=int, default=SEED_DEFAULT, help="Deterministic random seed")
    parser.add_argument("--host", default=BROKER_HOST, help="MQTT broker host")
    parser.add_argument("--port", type=int, default=BROKER_PORT, help="MQTT broker port")
    parser.add_argument("--time-scale", type=float, default=1.0, help="Playback speed multiplier")
    parser.add_argument("--dry-run", action="store_true", help="Skip publishing")
    parser.add_argument(
        "--export-plan",
        type=Path,
        default=Path(DEFAULT_PCAP_NAME).with_suffix(".plan.json"),
        help="Path to save materialized publish plan",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    messages, counts = build_generation_plan(seed=args.seed, flag_text=FLAG)
    export_plan_json(messages, args.export_plan)

    print(
        f"[plan] total={counts.total} signal={counts.signal} decoy_a={counts.decoy_a} decoy_b={counts.decoy_b} "
        f"export={args.export_plan}"
    )

    publish_plan(
        messages=messages,
        host=args.host,
        port=args.port,
        time_scale=args.time_scale,
        dry_run=args.dry_run,
    )

    if not args.dry_run:
        print(f"[publish] Published {len(messages)} MQTT messages to {args.host}:{args.port}")
    else:
        print("[publish] Dry-run mode enabled, no MQTT traffic sent")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
