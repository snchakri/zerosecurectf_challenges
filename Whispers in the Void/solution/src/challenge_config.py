from dataclasses import dataclass


TRUE_FLAG = "zerosecurectf{the_real_deadend}"


@dataclass(frozen=True)
class ChallengeConfig:
    width: int = 48
    height: int = 48
    pcap_total_bits_target: int = 3200
    total_packets_target: int = 3600

    client_ip: str = "10.13.37.2"
    server_ip: str = "10.13.37.5"
    client_port: int = 41844
    server_port: int = 443

    base_delay_us: int = 9000
    quantum_delay_us: int = 1400
    jitter_us: int = 120

    seed_default: int = 1337
