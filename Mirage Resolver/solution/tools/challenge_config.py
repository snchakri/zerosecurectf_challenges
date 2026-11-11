"""Shared constants for Mirage Resolver challenge."""

from __future__ import annotations

CHALLENGE_NAME = "mirage_resolver"
ROOT_DIR_NAME = "ch5_mirage_resolver"
DEFAULT_PCAP_NAME = "mirage_resolver.pcap"

FLAG = "ZeroSecure_CTF{mirage_resolver_a_record_whisper_1337}"
FLAG_PREFIX = "ZeroSecure_CTF{"

SEED_DEFAULT = 20260418

DNS_CLIENT_IP = "10.23.7.44"
DNS_SERVER_IP = "10.23.7.53"
DNS_ZONE = "samavarthan.local."

EPHEMERAL_MIN = 49152
EPHEMERAL_MAX = 65535
SIGNAL_CLIENT_SPORT_START = 53000
SIGNAL_TXID_BASE = 0x5A00

SIGNAL_A_PREFIX = "10.0.0."
SIGNAL_TTL_SECONDS = 300

NOISE_A_PAIR_TARGET = 180
NOISE_TXT_PAIR_TARGET = 28
NOISE_NXDOMAIN_PAIR_TARGET = 40

CAPTURE_DURATION_SECONDS = 48.0
SIGNAL_WINDOW_START_SECONDS = 8.5
SIGNAL_PAIR_INTERVAL_SECONDS = 0.047
SIGNAL_PAIR_JITTER_SECONDS = 0.006
RESPONSE_DELAY_MIN_SECONDS = 0.0014
RESPONSE_DELAY_MAX_SECONDS = 0.0095

DECOY_FLAG_MESSAGES = (
    "ZeroSecure_CTF{txt_record_obviously_real}",
    "ZeroSecure_CTF{query_path_hidden_answer}",
    "ZeroSecure_CTF{dns_label_magic_flag}",
    "ZeroSecure_CTF{autoparser_follow_queries}",
)

DECOY_MISC_MESSAGES = (
    "maintenance-window-v2",
    "resolver-cache-refresh",
    "do-not-trust-surface-signals",
    "trace-id:73f5b41c",
)

SIGNAL_PAIR_COUNT_TARGET = len(FLAG)
TOTAL_QUERY_RESPONSE_PAIRS = SIGNAL_PAIR_COUNT_TARGET + NOISE_A_PAIR_TARGET + NOISE_TXT_PAIR_TARGET + NOISE_NXDOMAIN_PAIR_TARGET
TOTAL_PACKET_TARGET = TOTAL_QUERY_RESPONSE_PAIRS * 2
