# Challenge: Doombot Border Filter (rev_08_ebpf_packet_filter_bytecode)

**Category:** Reverse Engineering
**Difficulty:** Hard
**Format:** `zerosecure{...}`

---

## Scenario & Objective

Every packet that crosses into Latveria's inner network is frisked at the wire
by a Doombot sentry program -- a filter that lives at the very edge of the
interface, deciding in a single pass whether a frame may enter or must be
dropped on the floor. Doom trusts no general-purpose guard; he had this one
hand-stamped, instruction by instruction, so that only one precise frame ever
earns passage. Feed the sentry the right sequence of bytes and it waves the
packet through; present anything else and it silently discards it, telling you
nothing about where you went wrong.

CICADA3301 mirrored the sentry's program off a tap on the border link
(`dist/filter.bpf`) and recovered a stand-alone harness to run it
(`dist/ebpf_vm.py`), because the Doombot's native toolchain never leaves the
citadel. The filter carries no stored passphrase -- it transforms the packet on
the fly and checks the result, byte by byte, against values welded into its own
instructions. Read the program, understand the running key it folds through
each byte, and reconstruct the one packet it will pass.

The accepted packet is the flag.

## Provided Files
- `dist/filter.bpf` -- the sentry program: a flat array of 8-byte eBPF
  instructions (classic little-endian encoding).
- `dist/ebpf_vm.py` -- a small emulator for the eBPF subset the program uses,
  plus the harness ABI (see `dist/README`).
- `dist/README` -- instruction encoding, calling convention, how to run.

## How to run
```
python dist/ebpf_vm.py '<candidate>'       # or pipe the candidate on stdin
```
Prints `ACCEPTED ... (XDP_PASS)` and exits 0 for the correct packet; otherwise
`REJECTED (XDP_DROP)` and exit 1.
