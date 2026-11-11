#!/usr/bin/env python3
from pathlib import Path
import re,base64
from scapy.all import rdpcap,DNS,DNSQR,TCP,ICMP,Raw
ROOT=Path(__file__).resolve().parents[1]
packets=rdpcap(str(ROOT/"challenge"/'zerosecurectf_basic_auth.pcap'))
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        m=re.search(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)",bytes(pkt[Raw]),re.I)
        if m:print(base64.b64decode(m[1]).decode())
