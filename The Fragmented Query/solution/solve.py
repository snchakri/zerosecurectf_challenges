#!/usr/bin/env python3
from pathlib import Path
import re,base64
from scapy.all import rdpcap,DNS,DNSQR,TCP,ICMP,Raw
ROOT=Path(__file__).resolve().parents[1]
packets=rdpcap(str(ROOT/"challenge"/'zerosecurectf_dns_fragmented.pcap'))
parts={}
for pkt in packets:
    if DNS in pkt and pkt[DNS].qd:
        name=pkt[DNS].qd.qname.decode().split(".")[0]
        m=re.fullmatch(r"part(\d+)-(.+)",name)
        if m:parts[int(m[1])]=m[2]
joined="-".join(parts[k] for k in sorted(parts))
body=joined.removeprefix("zerosecurectf-").replace("-","_")
print("zerosecurectf{"+body+"}")
