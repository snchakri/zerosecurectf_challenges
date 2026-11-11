# GridLink — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# GridLink — official writeup

**Flag:** `zerosecurectf{m3t3r_r0llov3r_b1ll3d_1n_32_b1ts}` (static demo seed/flag;
per-instance in production via `ZSCTF_SEED` / `ZSCTF_FLAG`).


## The flaw

The gateway has two ways to buy kWh credit.

Retail `TOPUP` is honest — it prices credit in a 64-bit field:

```c
int64_t cost = (int64_t)units * (int64_t)g_cfg.tariff_paise;   // u16 units, wide math
if (g_state.wallet_paise < cost) { ... reject ... }
```

Enterprise `BLOCK` is not. It accepts a full 32-bit `units`, but computes the
rupee cost in a **32-bit** accumulator before widening:

```c
uint32_t units = rd_u32(body);                 // up to 300,000,000
...
uint32_t cost_paise = units * g_cfg.tariff_paise;   // 32-bit multiply -> wraps mod 2^32
if (g_state.wallet_paise < (int64_t)cost_paise) { ... reject ... }
g_state.wallet_paise  -= (int64_t)cost_paise;
g_state.meter_credits += (int64_t)units;            // but the register gets the FULL 64-bit units
```

The product `units * tariff_paise` is reduced modulo 2³². The *credit* applied to
the meter register is the full, un-wrapped `units`. Those two facts disagree:
pick a `units` whose cost **wraps back down to a few paise**, and the service
bills almost nothing while crediting hundreds of millions of kWh.

This is a textbook **CWE-190 / CWE-197** pairing: a real accounting system that
does money math in a 32-bit integer and the ledger in a 64-bit one. (It is the
same *family* as the source challenge's one-sided arithmetic guard — see
Lineage — but a different, trickier sub-class, reached through a binary protocol
and tuned so a single naive input does not win.)


## Why honest play cannot win

The register ceiling (`maint_threshold`, ~1 × 10⁹ kWh per instance) is far above
anything the retail path can fund. With an opening balance of ~₹400–₹600 and a
tariff of ₹5–₹9/kWh, honest topping-up buys ~70 kWh total. `TOPUP` uses 64-bit
math, so it never wraps. The only way to the ceiling is the `BLOCK` truncation.


## Exploitation

The service publishes the four numbers you need in its banner, so the block
sizes are **computed, not guessed**:

```
config tariff_paise 555
config wallet_paise 43415
config maint_threshold 1033596885
config max_block 300000000
```

1. Find the largest affordable wrapping block. We want
   `units * tariff ≡ r (mod 2³²)` with `r ≤ wallet` and `units ≤ max_block`,
   maximising `units`. Because `r = ceil(k·2³²/tariff)·tariff − k·2³² ∈ [0,tariff)`
   for integer `k`, *every* `k` yields a residue smaller than one rupee; just
   take the largest `k` whose `units = ceil(k·2³²/tariff)` stays `≤ max_block`.
   For the banner above: `units = 294,069,833`, real price ₹1.63 billion, but
   **billed 67 paise**.
2. Send `BLOCK` repeatedly (each adds `units` kWh for ~₹0.67) until the register
   crosses `maint_threshold`. Here that is 4 blocks → meter ≈ 1.18 × 10⁹.
3. Send `DIAG`. The register is past the ceiling, so the gateway prints
   `DIAG unlocked` and the `FLAG` line.

Total cost ≈ ₹2.68 of a ₹434 balance; at most 4 requests across the whole
parameter space (verified by sweep). See [`solution/solve.py`](solution/solve.py).


## The §7 decoy (and why it is a dead end)

`ADJUST` is the obvious-looking target: it mutates the kWh register directly
with a *signed* `delta`, which screams "just send a huge or negative delta".
Two guards kill it:

- **PIN gate.** `ADJUST` requires a 32-bit `tech_pin` derived from `ZSCTF_SEED`
  and **never transmitted**. Guessing it is 2³² tries over a slow framed
  protocol — not a CTF path.
- **Hard bound.** Even *with* the PIN, each adjustment is clamped to `±100` kWh.
  Reaching ~10⁹ would take ~10⁷ authenticated calls.

A solver who reads the source sees both guards and discards `ADJUST` within a
minute, then looks at the billing paths. The acceptance test asserts the decoy
can neither authenticate nor unlock the diagnostic.


## Lineage (for the ZSCTF team)

- **Source inspiration:** `snchakri/zerosecurectf2026_challenges:
  binary_exploitation/ch1_negative_balance` — borrowed the *mechanic* (a crafted
  numeric input slips past a one-sided arithmetic guard to inflate a balance past
  a win threshold), **reskinned not copied**: new scenario (micro-grid metering),
  new transport (binary protocol vs text menu), new bug sub-class (32-bit cost
  truncation vs plain signed-quantity sign bug), new numbers, and a new decoy.
  Operator: **SUBSTITUTE-TARGET**.
- **Closest corpus seed:** `zsctf-anchor-001` ("unexploitable", a pwn crux
  reservoir) — operator **GROUND** (a toy pwn crux grounded into a realistic,
  query-driven service); plus **CONSTRAIN** (an online framed-protocol service,
  not a static dump), echoing `zsctf-crypto-017`. See `corpus-genome.yaml` and
  `challenge.yml`.
- **Harder variants (extrapolation).** Make the wrap exploit a single-shot by
  raising `max_block` past the ceiling (**PARAMETERISE**); or hide the banner so
  the solver must *infer* the tariff from a probe purchase (**CONSTRAIN**); or
  swap the truncation for a signed-mix comparison so the affordable window is a
  specific negative value (**SUBSTITUTE-PRIMITIVE**). Each raises the search axis
  without changing the primitive family.

## Local binary

The event backup omitted the downloadable binary. `challenge/gridlink` is a Linux x86-64 rebuild from the archived challenge source. It uses the same documented build flags; it is not claimed to be byte-identical to the event host.

```bash
python solution/solve.py --local challenge/gridlink
```
