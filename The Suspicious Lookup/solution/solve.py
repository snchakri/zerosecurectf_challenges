#!/usr/bin/env python3
from pathlib import Path
import re,base64
from scapy.all import rdpcap,DNS,DNSQR,TCP,ICMP,Raw
ROOT=Path(__file__).resolve().parents[1]
packets=rdpcap(str(ROOT/"challenge"/'zerosecurectf_dns_lookup.pcap'))
for pkt in packets:
    if DNS in pkt and pkt[DNS].qd:
        name=pkt[DNS].qd.qname.decode().rstrip(".")
        if name.startswith("zerosecurectf-"):
            body=name.split(".")[0].removeprefix("zerosecurectf-").replace("-","_")
            print("zerosecurectf{"+body+"}")
