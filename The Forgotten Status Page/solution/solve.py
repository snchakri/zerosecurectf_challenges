#!/usr/bin/env python3
from pathlib import Path
import re,base64
from scapy.all import rdpcap,DNS,DNSQR,TCP,ICMP,Raw
ROOT=Path(__file__).resolve().parents[1]
packets=rdpcap(str(ROOT/"challenge"/'zerosecurectf_flag.pcap'))
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        for flag in re.findall(rb"zerosecurectf\{[^}]+\}",bytes(pkt[Raw])):print(flag.decode())
