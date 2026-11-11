# Challenge: Thompson NFA with Epsilon Transitions (rev_12_non_deterministic_finite_automaton_nfa)

**Category:** Reverse Engineering
**Difficulty:** Extreme
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Binary/Runtime Internals

---

## Scenario & Objective
Doom distrusts simple locks, so the citadel's deepest gate is wired as a swarm.
A single compiled machine — recovered intact by CICADA3301 — evaluates a
submitted key by lighting up *many* internal states at once, firing on empty
transitions before it has even read a character, and letting the swarm of active
states collapse step by step as each symbol is consumed. Only if the one true
accept-state is still alight at the end does the gate open.

The automaton is seeded with decoy garrisons: whole clusters of states that look
live, consume plausible symbols, and lead absolutely nowhere. And the symbols the
machine checks are not your keystrokes directly — the gate first folds your input
through a running, position-dependent scrambler, so the letters the automaton
accepts are not the letters of the key.

Your objective: reverse the machine, find the one route through the swarm that
actually reaches acceptance, and unfold it back into the key the gate was built
to admit.

## Provided Files
- `dist/nfa_check` — a static Linux x86-64 ELF. Supply a candidate key as the
  first argument or on standard input.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. The accepted language is exactly one string.
