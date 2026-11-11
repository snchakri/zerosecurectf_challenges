#!/usr/bin/env python3
from pathlib import Path
import re,base64
from scapy.all import rdpcap,DNS,DNSQR,TCP,ICMP,Raw
ROOT=Path(__file__).resolve().parents[1]
packets=rdpcap(str(ROOT/"challenge"/'zerosecurectf_icmp_exfil.pcap'))
parts={}
for pkt in packets:
    if ICMP in pkt and pkt[ICMP].type==8 and pkt[ICMP].seq in [1,2,3] and Raw in pkt:
        parts[pkt[ICMP].seq]=bytes(pkt[Raw]).strip()
print(base64.b64decode(b"".join(parts[k] for k in [1,2,3])).decode())
