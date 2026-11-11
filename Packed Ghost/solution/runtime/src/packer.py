#!/usr/bin/env python3
"""
PACKED GHOST - packer.

Reads the compiled payload ELF, XOR-encrypts it, and emits stub.c: a loader
that carries the encrypted payload, decrypts it at runtime to a temp file and
execs it. The EGG and BAIT strings live in the STUB (so they survive in the
packed binary and show up in `strings`); the EARNED-FAKE lives only inside the
encrypted payload (invisible until you decrypt/run).

Invoked by build.py inside the container with:
    python3 packer.py <payload_elf> <stub_c_out>
"""
import sys

BAIT = "DOOM{p4ck3d_n0t_pr0t3ct3d}"
EGG = "you unpacked a ghost. ghosts don't carry flags."
KEY = bytes([0x13, 0x37, 0xC0, 0xDE, 0x5A, 0xA5, 0x66, 0x99])


def main():
    payload_path, stub_out = sys.argv[1], sys.argv[2]
    payload = open(payload_path, "rb").read()
    enc = bytes(payload[i] ^ KEY[i % len(KEY)] for i in range(len(payload)))

    arr = ", ".join(str(b) for b in enc)
    key = ", ".join(str(b) for b in KEY)

    stub = f"""/* AUTO-GENERATED packed stub -- do not edit */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* semi-visible on the packed blob -- the bait */
const char *blob_tag = "packed blob tag // {BAIT}";
/* the ghost's parting words -- the egg, only in the stub */
const char *ghost = "{EGG}";

static const unsigned char key[] = {{ {key} }};
static unsigned char payload[] = {{ {arr} }};
static const unsigned int payload_len = {len(enc)};

int main(void)
{{
    for (unsigned int i = 0; i < payload_len; i++)
        payload[i] ^= key[i % sizeof(key)];

    char path[] = "/tmp/.ghostXXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {{ perror("mkstemp"); return 1; }}
    if (write(fd, payload, payload_len) != (ssize_t)payload_len) {{
        perror("write"); return 1;
    }}
    close(fd);
    chmod(path, 0755);
    execl(path, path, (char *)NULL);
    perror("exec");
    return 1;
}}
"""
    with open(stub_out, "w", newline="\n") as f:
        f.write(stub)
    print(f"[packer] payload {len(payload)} bytes -> encrypted stub {stub_out}")


if __name__ == "__main__":
    main()
