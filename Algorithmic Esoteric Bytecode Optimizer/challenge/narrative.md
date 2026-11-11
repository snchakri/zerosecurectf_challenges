# Challenge: Brainfuck JIT Transpiler (misc_12_esoteric_brainfuck_jit_transpiler)

**Category:** Miscellaneous
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Compiler Reality

---

## Scenario & Objective
One of Doom's relay machines speaks only in the eight-symbol tongue -- a tape, a
pointer, and a fistful of primitive commands. CICADA3301 recovered the tape
image it runs on boot, the program that prints the citadel's inner service key.

There is a catch, and it is deliberate. The program is bloated with vast,
pointless runs of arithmetic and a dead loop that counts into the millions. Feed
it to a patient, one-instruction-at-a-time interpreter and you will wait, and
wait, and the relay will have long since rotated its key. The machine's own
engineers never run it that way. They compile it.

## Provided Files
- `dist/program.bf` -- the Brainfuck program. A leading comment block (letters
  and spaces only -- no command characters) carries flavour text; the rest is
  the program.

## Your Task
Execute the program and read what it prints. You will almost certainly need to
optimise before you run it: collapse the redundant arithmetic and fold the loop
idioms so the whole thing evaluates instantly. Its output is the flag.

## Compliance
- Flag format: `zerosecure{...}`
- Zero unreasoned guessiness. The output is fully determined by the program.
