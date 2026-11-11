#!/usr/bin/env python3
"""
Real solver for misc_05_serial_uart_logic_analyzer_vcd.

Reads ONLY dist/uart_trace.vcd. Steps:
  1. Parse the VCD: timescale + the identifier of the 1-bit wire, and every
     (time, level) change on it. Reconstruct a piecewise-constant level(t).
  2. Recover the bit period T purely from the waveform: it is the GCD of all
     gaps between consecutive level changes (every edge lands on a bit
     boundary, so every gap is an integer multiple of T).
  3. For each falling edge (idle-high -> start-bit-low), sample the 8 data bits
     at their bit centres (LSB first) and verify the stop bit is high.
  4. Concatenate the decoded bytes -> the flag.

Does not contain the flag and never reads the ./flag file.
"""
import argparse
import os
import re
from math import gcd


def parse_vcd(path):
    timescale = None
    var_id = None
    events = []          # (time_ns, level)
    cur_time = 0
    in_defs = True
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if in_defs:
            if line.startswith("$timescale"):
                m = re.search(r"(\d+)\s*([a-z]*s)", line)
                if m:
                    num = int(m.group(1))
                    unit = m.group(2)
                    scale = {"s": 1e9, "ms": 1e6, "us": 1e3, "ns": 1, "ps": 1e-3}
                    timescale = num * scale.get(unit, 1)
            elif line.startswith("$var"):
                # $var wire 1 ! rx $end
                parts = line.split()
                var_id = parts[3]
            elif line.startswith("$enddefinitions"):
                in_defs = False
            i += 1
            continue
        # value-change section
        if line.startswith("$dumpvars") or line == "$end" or line.startswith("$"):
            # handle inline value lines inside $dumpvars too
            if line.startswith("$dumpvars"):
                i += 1
                continue
            i += 1
            continue
        if line.startswith("#"):
            cur_time = int(line[1:])
        elif line and var_id and line[-len(var_id):] == var_id and line[0] in "01xzXZ":
            val = line[0]
            lvl = 1 if val == "1" else 0
            events.append((cur_time, lvl))
        i += 1
    return timescale, events


def level_fn(events):
    times = [e[0] for e in events]
    vals = [e[1] for e in events]

    def level_at(tq):
        # last event with time <= tq
        lo, hi = 0, len(times) - 1
        v = vals[0]
        import bisect
        idx = bisect.bisect_right(times, tq) - 1
        if idx < 0:
            idx = 0
        return vals[idx]
    return level_at


def recover_period(events):
    diffs = [events[i][0] - events[i - 1][0] for i in range(1, len(events))]
    diffs = [d for d in diffs if d > 0]
    g = 0
    for d in diffs:
        g = gcd(g, d)
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    path = os.path.join(args.dist, "uart_trace.vcd")
    _, events = parse_vcd(path)
    T = recover_period(events)
    level_at = level_fn(events)

    out = bytearray()
    # scan chronologically for start bits (falling edges from idle high)
    i = 1
    end_time = events[-1][0]
    while i < len(events):
        t_ev, lvl = events[i]
        if lvl == 0 and level_at(t_ev - 1) == 1:
            t0 = t_ev                          # start bit begins here
            byte = 0
            for k in range(8):
                centre = t0 + int(round((k + 1.5) * T))
                byte |= (level_at(centre) & 1) << k
            # stop bit sanity (centre of 10th slot) should be high
            stop = level_at(t0 + int(round(9.5 * T)))
            if stop != 1:
                i += 1
                continue
            out.append(byte)
            # jump to end of this frame and continue
            frame_end = t0 + 10 * T
            while i < len(events) and events[i][0] < frame_end:
                i += 1
            continue
        i += 1

    print(out.decode())


if __name__ == "__main__":
    main()
