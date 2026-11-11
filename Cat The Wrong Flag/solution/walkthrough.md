# CAT THE WRONG FLAG — author walkthrough

There is no flag file and nothing in `strings`. The flag is stored
XOR-0x5A-encrypted in `vault[]`; `open_vault()` decrypts and prints it but
`main()` never calls it.

1. `vuln()` does `read(0, buf, 0x200)` into `char buf[64]` — stack overflow.
2. Offset to the saved return address: **72** (64 + 8 saved rbp).
3. Overwrite it with the address of `open_vault()` (no PIE → static address).
4. Add one `ret` gadget first, so the stack is 16-byte aligned when
   `open_vault()` calls `puts()` (otherwise `movaps` faults).

Result: `ZeroSecure{c0ntr0l_fl0w_0p3ns_th3_v4ult}`.

`python3 solve.py` (needs pwntools; the shipped libc/ld let it run anywhere).
