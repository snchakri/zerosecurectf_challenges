# Whistler — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/whistler.wav
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Whistler — intended solution & design notes

**Category:** forensics · **Band:** Hard · **Flag:** `zerosecurectf{...}` (from `ZSCTF_FLAG`)
Default artifact flag: `zerosecurectf{mfsk_subcarrier_dekeyed_from_the_capture_nonce}`

---


## 1. The artifact

A single mono 16-bit PCM WAV at 44100 Hz, ~14.7 s. It plays as low broadband
hiss with a faint, restless warble. Casual listening and byte-level tools
(`strings`, `binwalk`, hex scan) reveal nothing of the flag — by construction
the flag never appears as bytes in the file. The hidden data is in the
**frequency domain** and it is **keyed**.


## 2. Intended solution (pure signal analysis of this file)

### Step 1 — look, don't listen: the spectrogram

Open the file in Audacity / Sonic Visualiser, or compute an STFT in Python. A
spectrogram shows the "hiss" is not empty: in the 1–6 kHz region a single faint
tone is present at any instant, and it **hops** between a small set of discrete
frequencies, changing roughly every 0.1 s. Measuring the tones shows they fall
on an evenly spaced grid of **16** frequencies:

```
f[k] = 1200 + 300·k  Hz ,  k = 0 … 15        # 1200, 1500, …, 5700 Hz
```

One of 16 frequencies per 0.1 s slot ⇒ this is **16-ary FSK**: each symbol
carries **4 bits (one nibble)**. (The grid is deliberately placed so each tone
lands exactly on an FFT bin at a 4410-sample window — 44100/4410 = 10 Hz bin
width, and every grid frequency is a multiple of 10 — so each tone is a clean,
leakage-free single-bin peak.)

### Step 2 — demodulate the tone indices

Slice the audio into 4410-sample windows starting at sample 0. For each window,
take an FFT and read the magnitude at the 16 grid bins (bin = f·4410/44100 =
f/10). The largest is the emitted grid index `p_i ∈ 0..15`. The detection margin
is large (the correct bin beats the next grid bin by >100× on payload symbols),
so this is exact, not statistical.

Decoding the indices straight to nibbles gives **garbage** — no readable text,
no magic. The stream is whitened. That is the "keyed" part.

### Step 3 — find the key: the capture nonce

Walk the RIFF chunks (or just `strings` the header). Besides `fmt ` and `data`
there is a `LIST`/`INFO` chunk whose `ICMT` comment reads, e.g.:

```
ambient subcarrier capture; nonce=7f3a…(32 hex); keystream=sha256-ctr(nonce)
```

So the file hands you (a) a 16-byte **nonce** and (b) the construction of the
keystream. This is the discoverable in-file parameter.

### Step 4 — reproduce the keystream and de-whiten

Expand a keystream from the nonce with SHA-256 in counter mode and read it as
nibbles (high nibble first):

```
block(c) = SHA256( nonce ‖ "whistler/ks|" ‖ uint32_be(c) ),  c = 0,1,2,…
keystream nibbles k_0, k_1, …  (each byte → high nibble, then low nibble)
```

Recover each payload nibble by undoing the XOR whitening:

```
v_i = p_i XOR k_i
```

### Step 5 — reassemble and verify the frame

Pack the recovered nibbles back into bytes (high nibble first) to get a
self-describing, self-verifying frame:

```
MAGIC(4)="ZSWR" | VER(1)=1 | LEN(2, big-endian) | FLAG(LEN) | CRC32(4, big-endian)
```

`CRC32` is `zlib.crc32` over `MAGIC‖VER‖LEN‖FLAG`. The magic and CRC make
correct recovery unambiguous: a wrong key, wrong nibble order, wrong symbol
alignment or wrong bin mapping fails the MAGIC/CRC check; the right procedure
passes it and yields the flag. There is nothing to brute-force.

The reference solver [`solution/solve.py`](solution/solve.py) does exactly this in a
few lines of numpy + stdlib and prints the flag. It does **not** import the
generator — it reconstructs the method from the (documented, in-file) spec.

### Why the stated facts are verifiable

- *Grid is on exact FFT bins:* 44100/4410 = 10 Hz; every `f[k]` is a multiple of
  10, so `f[k]·4410/44100` is an integer bin. (Checked in `test/` and by the
  >100× per-symbol detection margin measured on the default artifact.)
  flag nor `zerosecurectf{` occurs in the raw WAV; the flag only exists after
  FFT + de-whitening + frame parse.
- *Keyed + deterministic:* the keystream is a pure function of the in-file
  per-instance recovery (different seed ⇒ different bytes, still recoverable).


## 3. Why this is fair and not guessy (the §19 invariant)

Every step has a reasoning handle, so the design does not violate the "no
guessing" invariant (system.html §2, §19):

| Could be guessed? | The tell that removes the guess |
|---|---|
| "Is there hidden data at all?" | the spectrogram visibly shows 16 hopping tones |
| "What modulation?" | a discrete, evenly spaced 16-tone grid ⇒ 16-ary FSK |
| "Where's the key?" | a `nonce=` value sits in the `LIST/INFO` metadata |
| "How is it keyed?" | the same comment names `keystream=sha256-ctr(nonce)` |
| "Did I get it right?" | the `MAGIC`+`CRC32` frame validates or it doesn't |

This is the discipline system.html §18-B demands for the signal-to-noise knob:
*"noise with no tell → guessiness."* Here the noise bed hides the payload from
casual inspection and raises the signal-to-noise difficulty, but every layer
leaves a concrete tell, so the path is reasoning-recoverable end to end.


## 4. Red-team / AI-resistance

**Honest banding first.** This is a **Hard** challenge, not Frontier. By the
ZSCTF band definitions (system.html §8), Hard means "a strong individual solves
in hours; typically solvable by a capable agent." We do **not** claim this is
unsolvable by an AI agent. We claim the differential is real but modest, and we
say exactly where it lives.

**How an AI agent would attempt it.**
1. Run `file`, `strings`, `binwalk`, `exiftool`, `xxd` on the WAV. These find
   the `LIST/INFO` comment (good — intended) but no flag bytes (correct).
2. Recognise "audio stego" and reach for an LSB extractor / `zsteg`-style tool.
   **This fails**: there is no LSB payload. The LSBs are just the dithered sum
   of a tone and a noise bed; extracting them yields noise.
3. Compute a spectrogram and notice the tone grid. A capable agent *can* do
   this and *can* identify FSK — these are standard DSP moves well represented
   in training data.
4. Read `nonce=` and `keystream=sha256-ctr(nonce)` from the comment and
   implement the keystream. Applying a documented SHA-256-CTR keystream is a
   task LLMs are strong at.

**Where agents actually stumble (the real differential).** The friction is not
any single exotic trick; it is the *multi-step, self-consistent assembly* under
a noisy signal, where several independent conventions must all be right at once
before the CRC turns green:

- **Noise-filtering / orientation.** The payload is one faint tone under a
  broadband bed; the agent must decide *to stop byte-scanning and move to the
  frequency domain*. "Fraction of relevant material is low" is a documented
  agent weakness (system.html §18-B: signal-to-noise ⇒ "↑↑ AI-differential").
- **Exact framing conventions with no feedback until the end.** Symbol window =
  4410 samples *starting at sample 0*; nibble order = high-then-low; keystream
  nibble order must match; XOR direction; big-endian LEN/CRC; CRC covers
  `MAGIC‖VER‖LEN‖FLAG` only. Any one wrong ⇒ CRC fails with no partial credit
  and no hint as to which convention was off. Agents tend to thrash here.
- **Bin alignment.** Choosing a window length that puts the grid off-bin smears
  energy across neighbours and corrupts the argmax; the solver must reason out
  the 4410-sample window (or justify an equivalent) rather than guess an FFT
  size.

**Is the resistance real?** Partially, and we are not overstating it. A strong
agent with good tool access can plausibly solve Whistler within a normal budget;
the value is as a *Hard* forensics item that (a) rewards correct DSP reasoning,
(b) punishes the default "run every stego tool" reflex, and (c) is **per-instance
parameterised** so a memorised walkthrough does not transfer. The genuinely
AI-hard regimes (long-horizon, novel formalism) are explicitly *not* claimed
here — see the band note.

**The mechanism rejects guessing.** Because positions-in-frequency and the
nibble values are both pinned by the nonce-derived keystream and gated by a
CRC, there is no fruitful brute force: the 4-bit-per-symbol whitening over ~150
symbols is ~600 bits of key material that only the documented KDF reproduces,
and any deviation fails the CRC. You either reconstruct the method or you get
nothing — the defining property of a *keyed, reasoning-recoverable* stego task.

**Contamination note.** The *techniques* (FSK, spectrograms, SHA-256-CTR,
CRC32) are all in the public domain and in LLM training data — deliberately, so
the challenge is fair. What is **not** in any corpus is *this instance*: the
flag, the nonce, the resulting tone sequence and noise bed are generated per
team from `ZSCTF_SEED`/`ZSCTF_FLAG`, so no public writeup, cached solution, or
prior solver output can be replayed. A leaked solution for one team is inert for
leak would break all instances; secrecy lives only in the per-instance seed.

**Human–AI differential (summary).** Humans with a forensics habit tend to go
to a spectrogram quickly, *see* the hopping tones, and treat the metadata comment
as the obvious key — the visual gestalt does a lot of work. Agents are strong at
the FFT and the keystream once pointed there, but weaker at the orientation step
("this is spectral, not LSB") and at holding six exact conventions consistent
with zero feedback until the final CRC. Net: a modest, real edge to a trained
human analyst at the *orientation* and *assembly* steps; near-parity once the
method is correctly framed.


## 5. Lineage (corpus deconstruction → reconstruction)

Grounded in `corpus-genome.yaml` and `system.html` (§16, §17, §18-B).

- **Category:** forensics / DFIR (system.html §16 table: 12 verified seeds, all
  R-class — reconstructions of real incidents).
- **The gap (EXTRAPOLATE target).** system.html §16, the forensics note
  (the "E · Forensics / DFIR (12)" subsection): *"No rigorously designed,
  difficulty-evidenced steganography challenge could be verified — none was
  added to pad the list."* Steganography is therefore a **hole** in the corpus
  point-cloud. Per §10/§17, frontier and fair novelty come from extrapolating
  **into** such a gap — provided the new point does not reintroduce guessiness
  (§2). Whistler is that deliberate extrapolation: a *rigorously designed,
  difficulty-evidenced, keyed* stego challenge, with its fairness evidenced by
- **Operators applied (system.html §17.3).**
  - `EXTRAPOLATE` (Primitive extension / Adversarial-multimodal, §10) — push
    stego, absent from the corpus, into an audio/DSP artifact.
  - `GROUND` (G9,G3) — attach a benign, concrete scenario (a field-recording
    "capture") and a documented, keyed mechanism, so the extrapolation stays
    fair and self-contained rather than abstract.
  - `CONSTRAIN` (G4) — visibility is spectral-only: the payload is not
    byte-readable, forcing the frequency-domain path.
  - `PARAMETERISE` (any knob) — `ZSCTF_SEED` → nonce → keystream/noise, giving
    equally-hard per-instance variants (§24).
- **Affordance donors (genome `affordances`).**
  - `zsctf-forensics-007` *Gh0stNet Intrusion* — crux *"signal in noise,"*
    affordances `[CONSTRAIN, PARAMETERISE]`, `reconstruct_idea: "tune noise
    level (SNR knob, §18-B)."` We borrow **only the abstract signal-in-noise
    crux shape and the SNR knob** and re-cast them benignly (see Safety). The
    SNR between the FSK tone (~ -31 dBFS) and the noise bed (~ -46 dBFS) is the
    tunable difficulty knob.
  - `zsctf-forensics-011` *randomware* — affordance `PARAMETERISE`
    (*"per-instance weak key"*) supports the per-instance keystream here.
- **Knob (system.html §18-B).** Signal-to-noise: ↑ difficulty, ↑↑ AI-differential
  ("noise filtering is an agent weakness"), with the explicit caveat *"noise
  with no tell → guessiness"* — which §3's tells are designed to satisfy.
- **Class / banding.** Static-artifact delivery (§23: "file delivery + integrity
  hash; no live service; flag inside the artifact or per-instance §24"),
  forensics "medium–hard, regenerate the artifact per seed" (§23 table) → **Hard**.


## 6. Safety / scope

Benign by construction and by intent. Whistler is **media/signal forensics**: a
synthesized ambient audio file with a keyed hidden message, solved by DSP plus a
documented keystream. It is **not** malware, not a beacon, not C2, not network
traffic, and nothing in it is weaponizable. Although affordance donor
`forensics-007` is literally C2-beaconing, we imported **only** its abstract
"signal in noise" shape and its SNR knob and deliberately re-grounded them as
*hidden tones in an ordinary recording* — no attack traffic, no implant, no
network surface. The Docker image is a generator that writes a file and exits
(`network_mode: none`, read-only root FS, all caps dropped, non-root).
