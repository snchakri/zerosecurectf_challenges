# Staged Hint Ladder: Thompson NFA with Epsilon Transitions

### Hint Level 1 (Orientation)
The binary carries its automaton as a data table, bracketed by an ASCII magic
marker (`Z5NFA_v1` ... `Z5NFAEND`). Find that region. It encodes a state count,
start and accept state ids, three small transform constants, a list of epsilon
edges `(from, to)`, and a list of symbol edges `(from, byte, to)`. The engine
does classic epsilon-closure set simulation.

### Hint Level 2 (Reframe)
Note the three constants (`A0`, `K`, `C`): before simulation the program maps
input `x` to `y[i] = (x[i] + acc_i) & 0xff` with
`acc_{i+1} = (acc_i*K + y[i] + C) & 0xff`, `acc_0 = A0`. So the automaton accepts
a scrambled string `Y`, not the key. Decoy states exist only to add noise — they
can never reach the accept state.

### Hint Level 3 (Strong Nudge)
Compute, by reverse reachability over all edges, which states can still reach the
accept state. Then walk forward with epsilon-closure: at each step exactly one
symbol byte moves an accept-reachable state to another accept-reachable state —
that byte is the next `Y` byte. Recover all of `Y`, then invert the `acc` chain
(`x[i] = (y[i] - acc_i) & 0xff`) to get the key. No search over decoys, no brute
force.

---
*Note: Crux Floor invariant: The core reverse engineering insight is never handed out completely; each hint restores a reasoning handle.*
