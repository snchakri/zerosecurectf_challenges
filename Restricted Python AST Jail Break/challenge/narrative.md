# Challenge: Restricted-AST Python Jail (misc_04_pyjail_ast_restricted_subset)

**Category:** Miscellaneous
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Scripting Reality

---

## Scenario & Objective
Doom permits his vassals a single indulgence: a sealed computational sandbox in
the citadel's undercroft, where they may submit *one* Python expression and
receive its value. The sandbox is miserly. It forbids underscores and dots,
quotes and brackets; it parses what you send and rejects anything that reaches
for an attribute, a subscript, or a string literal. Within those walls sits a
sealed record the tyrant believes no vassal can read.

He is almost right. The record is present, but scrambled, and the undercroft's
own primitives are enough to unscramble it -- *if* you can coax the sandbox into
performing an operation it seems designed to forbid. The art is not brute force;
it is finding the one legal shape of an expression that does the illegal thing.

## Provided Files
- `dist/jail.py` -- the sandbox. Run it and submit one expression on standard
  input. It enforces the restrictions itself and prints the value of an accepted
  expression. The sealed record lives inside it (encoded, never in plaintext).

## Your Task
Craft an expression that satisfies every restriction yet forces the sandbox to
reveal what the sealed record really says. Running the shipped jail with your
expression prints the flag -- no network, no external files.

## Compliance
- Flag format: `zerosecure{...}`
- Zero unreasoned guessiness. The payload is a construction, not a guess.
