# Thompson NFA with Epsilon Transitions — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Thompson NFA with Epsilon Transitions (Automata Reversal)


## 1. Analysis & Theoretical Foundations
`dist/nfa_check` is a static x86-64 ELF implementing a Thompson-style NFA with
explicit epsilon transitions and classic epsilon-closure set simulation. Its
accepted language is exactly one string `Y`. Input is **not** matched directly:
the program first folds the candidate through a position-chained transform `T`
and feeds the result `Y` to the NFA. Decoy "trap" state clusters create genuine
non-determinism (multiple simultaneously-active states) but can never reach the
accept state.


## 2. Embedded automaton format
The table is bracketed by magic markers `Z5NFA_v1` ... `Z5NFAEND` (little-endian):
```
u16 n_states, u16 start, u16 accept
u8  A0, u8 K, u8 C                     # transform constants
u16 n_eps; n_eps * (u16 from, u16 to)  # epsilon edges
u16 n_sym; n_sym * (u16 from, u8 byte, u16 to)  # symbol edges
```
The transform `T` is:
```
acc = A0
y[i] = (x[i] + acc) & 0xff
acc  = (acc*K + y[i] + C) & 0xff
```
Because `Y = T(flag)` is what the NFA labels contain, the raw flag bytes never
appear in the binary (verified by the leak check).


## 3. Step-by-Step Walkthrough
1. Scan the ELF for the magic region and parse states, epsilon edges, symbol
   edges, `start`, `accept`, and `A0,K,C`.
2. Reverse-reachability: over all edges (epsilon + symbol), compute the set of
   states that can still reach `accept`. Trap states fall out of this set.
3. Reconstruct `Y`. Start from `eps_closure({start})`. Repeatedly: among active,
   accept-reachable states, find the unique symbol byte `b` whose transition
   lands on another accept-reachable state; append `b`; advance to
   `eps_closure(move(active, b))` pruned to accept-reachable states. Stop when
   `accept` is active. Uniqueness holds because only backbone transitions lead to
   accept-reachable targets.
4. Invert the transform: `x[i] = (y[i] - acc_i) & 0xff`, advancing `acc` with
   each `y[i]`. The result is the flag.


## 4. Why it resists shortcuts
- `strings` reveals nothing (stripped binary; only `Y`'s scrambled labels exist).
- A reader cannot just follow "the path": epsilon closures mean many states are
  active at once, and decoy transitions offer plausible-but-dead symbols at every
  step. You must do real NFA analysis (closure + reverse reachability).
- Fully deterministic recovery, O(states·edges·len) — no brute force.


## 5. Exploit Script & Verification
`solve.py` reads only the ELF in `dist/`:
```bash
python solve.py --dist ./dist
```
Prints the recovered `zerosecure{...}` key, byte-identical to `flag`. The binary
confirms independently: `./dist/nfa_check "<key>"` prints "ACCESS GRANTED".


## 6. Citations & References
- Thompson, K. (1968). *Programming Techniques: Regular expression search
  algorithm.* Communications of the ACM, 11(6), 419–422.
- Hopcroft, Motwani, Ullman (2006). *Introduction to Automata Theory, Languages,
  and Computation* (NFA, epsilon-closure, subset construction).
- Russ Cox. *Regular Expression Matching Can Be Simple And Fast* (Thompson NFA
  simulation).


## 7. Defense Engineering & Remediation
An NFA accepting a single fixed string is just an obfuscated string compare;
adding a transform and decoys raises reversing cost but provides no real secrecy.
Authenticate keys with a server-side slow hash, and treat client-side automata as
tamper-visible logic, not as a secret store.
