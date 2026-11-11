"""Shared constants for Rogue Edge Sensor challenge generation and validation."""

from __future__ import annotations

from dataclasses import dataclass

CHALLENGE_NAME = "rogue_edge_sensor"
ROOT_DIR_NAME = "ch1_rogue_edge_sensor"
DEFAULT_PCAP_NAME = "rogue_edge_sensor.pcap"

FLAG = "ZeroSecure_CTF{mqtt_decimal_whisper_win}"
FLAG_PREFIX = "ZeroSecure_CTF{"

CAPTURE_SECONDS = 300
BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883

TOPIC_SIGNAL = "samavarthan/halls/main/sensor1"
TOPIC_DECOY_A = "samavarthan/halls/main/sensor2"
TOPIC_DECOY_B = "samavarthan/halls/annex/sensor12"

TOPICS = (TOPIC_SIGNAL, TOPIC_DECOY_A, TOPIC_DECOY_B)
TOPIC_WEIGHTS = {
    TOPIC_SIGNAL: 0.15,
    TOPIC_DECOY_A: 0.55,
    TOPIC_DECOY_B: 0.30,
}

# Locked environmental envelopes.
TEMP_START = 23.0
TEMP_STEP_CHOICES = (-0.2, -0.1, 0.0, 0.1, 0.2)
TEMP_MIN = 21.8
TEMP_MAX = 25.2

HUMIDITY_BOUNDS = {
    TOPIC_SIGNAL: (43, 49),
    TOPIC_DECOY_A: (41, 53),
    TOPIC_DECOY_B: (35, 58),
}
HUMIDITY_STEP_CHOICES = (-1, 0, 1)

# Interval model lock.
BASE_INTERVAL_MIN = 1.5
BASE_INTERVAL_MAX = 3.0
JITTER_MIN = -0.5
JITTER_MAX = 0.5
INTERVAL_MIN = 1.0
INTERVAL_MAX = 3.5

# Count targets.
TOTAL_PUBLISH_MIN = 400
TOTAL_PUBLISH_MAX = 500
SIGNAL_COUNT_MIN = 60
SIGNAL_COUNT_MAX = 75
SIGNAL_RATIO_TARGET = 0.15
TOPIC_SHARE_TOLERANCE = 0.02

# We inject extra burst messages for sensor2 ticks to satisfy volume/share constraints.
DECOY_A_DUPLICATE_PROBABILITY = 0.80
DUPLICATE_OFFSET_SECONDS = 0.025

# Active windows (seconds from start) to keep signal topic in its packet-count band.
SIGNAL_ACTIVE_WINDOWS = ((20.0, 100.0), (170.0, 230.0))

SEED_DEFAULT = 20260418


@dataclass(frozen=True)
class TopicCounts:
    """Materialized publish counts per topic for one generation run."""

    total: int
    signal: int
    decoy_a: int
    decoy_b: int
