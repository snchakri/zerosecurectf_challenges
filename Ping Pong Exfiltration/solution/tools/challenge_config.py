"""Shared constants for Ping Pong Exfiltration challenge."""

from __future__ import annotations

CHALLENGE_NAME = "ping_pong_exfiltration"
ROOT_DIR_NAME = "ch2_ping_pong_exfiltration"
DEFAULT_PCAP_NAME = "ping_pong_exfiltration.pcap"

FLAG = "ZeroSecure_CTF{icmp_zip_chain_signal_1337}"
FLAG_PREFIX = "ZeroSecure_CTF{"

SIGNAL_IDENTIFIER = 0x1337
WINDOWS_PING_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"
PAYLOAD_SIZE_BYTES = len(WINDOWS_PING_PAYLOAD)

SIGNAL_SOURCE_IP = "10.90.14.23"
PING_TARGET_IP = "10.90.14.1"
DECOY_SOURCE_IPS = (
    "10.90.14.24",
    "10.90.14.25",
    "10.90.14.26",
    "10.90.15.5",
)

TOTAL_ECHO_REQUEST_TARGET = 300
TOTAL_ECHO_REQUEST_MIN = 290
TOTAL_ECHO_REQUEST_MAX = 310
MIN_DECOY_REQUESTS = 100

CAPTURE_DURATION_SECONDS = 45.0
REPLY_DELAY_MIN_SECONDS = 0.018
REPLY_DELAY_MAX_SECONDS = 0.085

SEED_DEFAULT = 20260418
