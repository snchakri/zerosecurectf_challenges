# ch5_mirage_resolver

**Category:** Network Forensics

# Mirage Resolver

A ghosted endpoint keeps talking to an internal resolver with query names that look like nonsense: update bursts, random labels, and fake operational chatter. It feels loud, suspicious, and almost too obvious.

But this network tale is all smoke and mirrors. The question names are stage props. The answer section is where the whispers live.

Your objective:
- Analyze the provided PCAP.
- Recover the single true flag from DNS traffic.
- Ignore bait strings that look like flags but do not validate.

Flag format:

ZeroSecure_CTF{...}

