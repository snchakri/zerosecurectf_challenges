# Challenge: Subgroup Giant Step (crypto_08_discrete_log_baby_step_giant_step)

**Category:** Cryptography
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
Doom's cipher-wrights boast that their access gate rests on the discrete
logarithm problem — "unbreakable mathematics," they engrave above the door. But
vanity chose the parameters. The public generator does not roam the whole
multiplicative group of the prime `p`; it is penned inside a small prime-order
subgroup. The gate publishes `p`, the generator `g`, and the challenge value
`h = g^x mod p`. The private exponent `x` is the session key, and the citadel's
flag is sealed under it.

Your objective: solve for `x` inside the cramped subgroup, then lift the seal.

## Provided Files
- `dlog_params.json` — `p`, `g`, `h`, the `subgroup_order`, the sealed flag
  (`sealed_flag_hex`), and an exact description of how `x` keys that seal.

## Sealing (so nothing is guessy)
The flag is `AES-256-GCM` over `nonce||ciphertext||tag = sealed_flag_hex`, with
`key = SHA256(b"zsctf-dlog|key|" + ascii(decimal(x)))` and
`nonce = SHA256(b"zsctf-dlog|nonce|" + ascii(decimal(x)))[:12]`, where `x` is the
discrete log of `h` to base `g` in the order-`subgroup_order` subgroup.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. `x` is uniquely determined and fully recovers the flag.
