# ch2_matryoshka_protocol - Verification

## Must pass

1. Wrapper decodes embedded payload without crash.
2. Payload executes expected behavior.
3. Temporary dropped executable is removed after execution.
4. Static decode route reproduces executable bytes.

## Evidence to store

- wrapper runtime log
- hash of regenerated payload from decode script
