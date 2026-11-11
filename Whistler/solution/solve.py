#!/usr/bin/env python3
"""
ZSCTF :: Whistler -- reference solver (standalone; does NOT import the generator).

Intended path -- pure signal analysis of THIS file, plus the documented,
discoverable keystream AND a second (order) plane:

  1. Parse the WAV. A spectrogram shows the "hiss" actually contains a faint
     tone that hops, every 0.1 s, among a fixed grid of 16 frequencies
     (1200 Hz + k*300 Hz, k = 0..15) -- Plane B, 16-ary FSK, 4 bits per symbol.
     ABOVE it, across the middle of the file, a SECOND, slower tone hops in a
     disjoint band (6000 Hz + k*100 Hz) -- Plane A.
  2. Read the capture nonce (and the terse two-plane spec) from the file's
     RIFF LIST/INFO (ICMT) metadata.
  3. Demodulate Plane B per 0.1 s symbol (FFT; argmax over the 16 grid bins) and
     de-whiten with the nonce keystream (SHA-256 counter mode, label
     "whistler/ks|"). This yields the de-keyed frame bytes -- the CRUX result.
     BUT the FLAG field is laid out as 8-nibble BLOCKS emitted in a scrambled
     time order, so reading them left-to-right gives a near-flag that fails CRC.
  4. Parse the header (MAGIC|VER|LEN). From LEN compute the number of body
     blocks NB. Demodulate Plane A -- one symbol per block over its
     BLOCK_NIBBLES-symbol span (FFT over the block window; argmax over Plane A's
     grid) -- and de-whiten with the nonce keystream (label "whistler/perm|").
     The result MUST be a permutation of 0..NB-1 (a verifiable check); it tells
     you, for each body time-slot j, the TRUE rank of the block there.
  5. REORDER Plane B's body blocks by that permutation, reassemble the frame
         MAGIC "ZSWR" | VER | LEN | FLAG | CRC32(4,BE)
     and verify CRC32 over MAGIC|VER|LEN|FLAG. Correct reorder passes; any other
     (including the naive left-to-right order) fails. Nothing is guessed.

Usage:
    python3 solve.py <path-to.wav>            # prints the flag (only) to stdout
    python3 solve.py --naive <path-to.wav>    # prints the NAIVE (single-plane,
                                              # left-to-right, no-reorder) near-flag
                                              # candidate -- a rejectable footgun
"""
import hashlib
import struct
import sys
import wave
import zlib

import numpy as np

# --- public carrier spec (same values the artifact is built to; see writeup) --
SAMPLE_RATE    = 44100
SYMBOL_SAMPLES = 4410
GRID_BASE_HZ   = 1200
GRID_STEP_HZ   = 300
GRID_SIZE      = 16

BLOCK_NIBBLES  = 8            # body block = 8 Plane-B symbols = 4 bytes
PA_BASE_HZ     = 6000
PA_STEP_HZ     = 100
PA_SIZE        = 16

MAGIC          = b"ZSWR"
KS_LABEL       = b"whistler/ks|"
PERM_LABEL     = b"whistler/perm|"

HEADER_SYMS    = 14          # MAGIC|VER|LEN = 7 bytes = 14 nibbles
CRC_SYMS       = 8           # CRC32 = 4 bytes = 8 nibbles


def grid_bins():
    """FFT bin index of each Plane-B grid tone at the symbol window (integers)."""
    return [(GRID_BASE_HZ + k * GRID_STEP_HZ) * SYMBOL_SAMPLES // SAMPLE_RATE
            for k in range(GRID_SIZE)]


def pa_bins(window):
    """FFT bin index of each Plane-A grid tone at a block window (integers)."""
    return [(PA_BASE_HZ + k * PA_STEP_HZ) * window // SAMPLE_RATE
            for k in range(PA_SIZE)]


def read_wav_samples(path):
    """Return mono int16 samples as a float array (stdlib wave)."""
    with wave.open(path, "rb") as w:
        assert w.getsampwidth() == 2, "expected 16-bit PCM"
        nch = w.getnchannels()
        frames = w.readframes(w.getnframes())
    data = np.frombuffer(frames, dtype="<i2").astype(np.float64)
    if nch > 1:
        data = data.reshape(-1, nch)[:, 0]   # take channel 0 if ever stereo
    return data


def read_nonce(path):
    """Extract the capture nonce (hex) from the RIFF LIST/INFO ICMT comment."""
    raw = open(path, "rb").read()
    assert raw[:4] == b"RIFF" and raw[8:12] == b"WAVE", "not a WAVE file"
    pos = 12
    comment = None
    while pos + 8 <= len(raw):
        cid = raw[pos:pos + 4]
        sz = struct.unpack("<I", raw[pos + 4:pos + 8])[0]
        body = raw[pos + 8:pos + 8 + sz]
        if cid == b"LIST" and body[:4] == b"INFO":
            p = 4
            while p + 8 <= len(body):
                sub = body[p:p + 4]
                ssz = struct.unpack("<I", body[p + 4:p + 8])[0]
                sdata = body[p + 8:p + 8 + ssz]
                if sub == b"ICMT":
                    comment = sdata.split(b"\x00", 1)[0].decode("utf-8", "replace")
                p += 8 + ssz + (ssz & 1)
        pos += 8 + sz + (sz & 1)
    if comment is None:
        raise ValueError("no ICMT metadata found")
    for tok in comment.replace(";", " ").split():
        if tok.startswith("nonce="):
            return bytes.fromhex(tok.split("=", 1)[1])
    raise ValueError("nonce not found in metadata comment: %r" % comment)


def ks_bytes(nonce, label, nbytes):
    """SHA-256 counter-mode keystream (same construction as the artifact)."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(nonce + label + struct.pack(">I", ctr)).digest()
        ctr += 1
    return bytes(out[:nbytes])


def ks_nibbles(nonce, label, count):
    kb = ks_bytes(nonce, label, (count + 1) // 2)
    nib = []
    for b in kb:
        nib.append((b >> 4) & 0xF)
        nib.append(b & 0xF)
    return nib[:count]


def demod_plane_b(samples, n_symbols):
    """FFT each symbol window; return the emitted Plane-B grid index per symbol."""
    bins = grid_bins()
    idx = []
    for i in range(n_symbols):
        seg = samples[i * SYMBOL_SAMPLES:(i + 1) * SYMBOL_SAMPLES]
        if len(seg) < SYMBOL_SAMPLES:
            raise ValueError("audio too short for symbol %d" % i)
        mag = np.abs(np.fft.rfft(seg))
        energies = [mag[b] for b in bins]
        idx.append(int(np.argmax(energies)))
    return idx


def demod_plane_a(samples, nb):
    """One Plane-A symbol per body block; return the emitted index per block."""
    window = BLOCK_NIBBLES * SYMBOL_SAMPLES
    bins = pa_bins(window)
    idx = []
    for j in range(nb):
        start = (HEADER_SYMS + j * BLOCK_NIBBLES) * SYMBOL_SAMPLES
        seg = samples[start:start + window]
        if len(seg) < window:
            raise ValueError("audio too short for Plane-A block %d" % j)
        mag = np.abs(np.fft.rfft(seg))
        energies = [mag[b] for b in bins]
        idx.append(int(np.argmax(energies)))
    return idx


def nibbles_to_bytes(nibs):
    out = bytearray()
    for i in range(0, len(nibs) - 1, 2):
        out.append((nibs[i] << 4) | nibs[i + 1])
    return bytes(out)


def _dekey_plane_b(samples, nonce):
    """Demod + de-whiten ALL Plane-B symbols -> (payload nibbles, n_symbols)."""
    max_symbols = len(samples) // SYMBOL_SAMPLES
    tone_idx = demod_plane_b(samples, max_symbols)
    ksb = ks_nibbles(nonce, KS_LABEL, max_symbols)
    nibs = [(tone_idx[i] ^ ksb[i]) & 0xF for i in range(max_symbols)]
    return nibs, max_symbols


def _parse_header(nibs):
    """Parse MAGIC|VER|LEN from the first HEADER_SYMS de-keyed nibbles."""
    head = nibbles_to_bytes(nibs[:HEADER_SYMS])
    if head[:4] != MAGIC:
        raise ValueError("MAGIC mismatch -- wrong key/alignment (got %r)" % head[:4])
    ver = head[4]
    (length,) = struct.unpack(">H", head[5:7])
    nb = (length * 2 + BLOCK_NIBBLES - 1) // BLOCK_NIBBLES
    return ver, length, nb


def recover(path):
    """FULL intended path: de-key Plane B, read Plane A, REORDER, verify CRC."""
    samples = read_wav_samples(path)
    nonce = read_nonce(path)

    nibs, _ = _dekey_plane_b(samples, nonce)
    ver, length, nb = _parse_header(nibs)
    if nb > PA_SIZE:
        raise ValueError("implausible LEN -> nb=%d > %d" % (nb, PA_SIZE))

    body_syms = nb * BLOCK_NIBBLES
    body = nibs[HEADER_SYMS:HEADER_SYMS + body_syms]
    crc_nibs = nibs[HEADER_SYMS + body_syms:HEADER_SYMS + body_syms + CRC_SYMS]

    # --- Plane A: recover the permutation and VERIFY it is a permutation ---
    pa_idx = demod_plane_a(samples, nb)
    ksa = ks_nibbles(nonce, PERM_LABEL, nb)
    perm = [(pa_idx[j] ^ ksa[j]) & 0xF for j in range(nb)]
    if sorted(perm) != list(range(nb)):
        raise ValueError("Plane-A did not de-whiten to a permutation of 0..%d "
                         "(got %r) -- wrong demod/alignment" % (nb - 1, perm))

    # --- reorder Plane B's body blocks: time-slot j holds true block perm[j] ---
    time_blocks = [body[j * BLOCK_NIBBLES:(j + 1) * BLOCK_NIBBLES]
                   for j in range(nb)]
    true_blocks = [None] * nb
    for j in range(nb):
        true_blocks[perm[j]] = time_blocks[j]
    padded = [n for blk in true_blocks for n in blk]
    flag_nibs = padded[:length * 2]
    fb = nibbles_to_bytes(flag_nibs)

    # --- verify the self-describing frame ---
    head = MAGIC + bytes([ver]) + struct.pack(">H", length) + fb
    (crc,) = struct.unpack(">I", nibbles_to_bytes(crc_nibs))
    if (zlib.crc32(head) & 0xFFFFFFFF) != crc:
        raise ValueError("CRC mismatch -- reorder/recovery not validated")
    return fb.decode("utf-8")


def recover_naive(path):
    """NAIVE single-plane read: de-key Plane B, take the body in LEFT-TO-RIGHT
    (identity) order WITHOUT consulting Plane A, and read off the flag field.
    MAGIC/VER/LEN still validate (footgun), but the flag is out of order. No CRC
    gate here -- this exists to demonstrate the rejectable near-flag."""
    samples = read_wav_samples(path)
    nonce = read_nonce(path)
    nibs, _ = _dekey_plane_b(samples, nonce)
    _, length, nb = _parse_header(nibs)
    body_syms = nb * BLOCK_NIBBLES
    body = nibs[HEADER_SYMS:HEADER_SYMS + body_syms]
    flag_nibs = body[:length * 2]            # identity order (no reorder)
    fb = nibbles_to_bytes(flag_nibs)
    return fb.decode("utf-8", "replace")


def main(argv):
    naive = False
    args = argv[1:]
    if args and args[0] == "--naive":
        naive = True
        args = args[1:]
    if len(args) != 1:
        sys.stderr.write("usage: solve.py [--naive] <path-to.wav>\n")
        return 2
    path = args[0]
    try:
        if naive:
            cand = recover_naive(path)
            sys.stderr.write("[!] naive single-plane read (no Plane-A reorder); "
                             "CRC NOT validated -- expect a rejectable near-flag\n")
            print(cand)
            return 0
        flag = recover(path)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] Plane-A permutation verified; frame validated "
                     "(MAGIC+CRC32 ok); flag recovered\n")
    print(flag)           # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
