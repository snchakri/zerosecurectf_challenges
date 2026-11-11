# Challenge: Golang Concurrent Channel Pipeline (rev_03_go_runtime_goroutine_channels)

**Category:** Reverse Engineering
**Difficulty:** Extreme
**Format:** `zerosecure{...}`

---

## Scenario & Objective

The Latverian foundry that forges Doom's war-plate runs on a conveyor of four
blind artisans. A character enters at one end; the first artisan nudges it by a
position-dependent amount, passes it down the belt; the second re-tempers it
against a secret key-ribbon; the third twists its bits and brands it; the fourth
subtracts a running tally of everything that has passed. CICADA3301 has lifted the
foundry's controller (`dist/rev03_pipeline`): four worker threads linked by
first-in-first-out channels. Only one input word survives all four stations and
matches the die Doom cast into the controller. Trace the belt, invert every
station in reverse order, and recover the word.

The accepted word is the flag.

## Provided Files
- `dist/rev03_pipeline` -- the foundry controller (stripped Linux x86-64 ELF, static; multi-threaded).

## How to run
```
./rev03_pipeline 'zerosecure{...}'      # or pipe the candidate on stdin
```
It prints an acceptance line and exits 0 for the correct word; otherwise
`rejected` and exit 1.
