# Contents

### PROJECT: NULL // 30-LAYER CRYPTOGRAPHIC INITIATION 1

```
Oﬀicial Solution Writeup......................................... 1
Challenge Metadata............................................ 1
How To Read This Solution........................................ 1
Challenge Overview............................................ 2
Live Structure............................................... 2
Backend Behavior Summary........................................ 3
Narrative Progression........................................... 3
Canonical Answer Note.......................................... 4
Full Solve Path............................................... 4
Act I — You Have Been Noticed..................................... 4
Act II — We Are Observing Your Thinking............................... 6
Act III — The Organization Reveals Its Fractures........................... 7
Act IV — Are You Solving, or Being Used?............................... 10
Act V — The Machine Has Always Been Listening........................... 12
Fragment Registry............................................. 13
Decoy Design Summary.......................................... 14
Final Assembly............................................... 15
Final Flag.................................................. 15
Expected Organizer Verification Flow.................................. 15
Closing Note................................................ 15
```
# PROJECT: NULL // 30-LAYER CRYPTOGRAPHIC INITIA-

# TION

## Oﬀicial Solution Writeup

This document is the organizer-side solution for the livePROJECT: NULLdeployment. It is written in the
same spirit as the existing challenge solution PDFs in the main CTF repository: it explains the intended
player experience, the real solve path, the decoy logic, the backend behavior, the fragment progression, and
the final flag.

## Challenge Metadata

- **Title:** PROJECT: NULL // 30-Layer Cryptographic Initiation
- **Author:** AniLog
- **Challenge Type:** Narrative / Cryptography / Web / Multi-stage
- **Format:** 30 sequential dossier pages with backend-validated keys
- **Flag Format:** zerosec{...}
- **Live Runtime:** Next.js static frontend + FastAPI + SQLite
This is a host-only document. It contains:
- canonical layer keys
- poisoned false-positive keys
- verified fragment outputs
- final assembly logic
- final flag

## How To Read This Solution

This writeup is intentionally stepwise.
For each layer, the important fields are:

- **Public asset**
    **-** the main downloadable or inspectable evidence file
- **Player-facing idea**
    **-** what the layer appears to be testing


- **Intended solve path**
    **-** the correct step-by-step reasoning flow
- **Canonical key**
    **-** the intended accepted answer
- **False-positive key**
    **-** the authored shallow-solver trap
- **Why the trap works**
    **-** why the wrong answer feels attractive
- **Verified fragment / Poison fragment**
    **-** what the backend actually awards
The intended organizer reading flow is:
1.Read the challenge overview and backend model.
2.Follow the act-by-act layer solutions in order.
3.Use the fragment registry and decoy summary to validate the challenge logic.
4.Use the final assembly section to verify the final flag.

## Challenge Overview

```
PROJECT: NULLis a 30-layer sequential cryptographic initiation challenge presented as a hostile recruitment
interface. The player is not solving a list of small prompts. The player is moving through one dossier page
at a time, with each page becoming available only after the current layer is solved.
Each layer follows the same gameplay contract:
1.The player reaches the currently unlocked dossier page.
2.The player reads the briefing and inspects the public evidence.
3.The player activates a timed window.
4.The player submits a key.
5.The backend responds with one of:
```
- correct
- incorrect
- false_positive
6.A correct solve awards a verified fragment and unlocks the next dossier.
The challenge is designed to punish shallow confidence instead of raw ignorance. A readable answer is often
not the intended answer. Several layers contain false-positive keys that return poisoned fragments. The
system therefore tests corroboration, provenance, chronology, metadata, and behavioral discipline, not only
decoding skill.

## Live Structure

```
Public Runtime Root
```
- PROJECT-NULL-LIVE/frontend
- PROJECT-NULL-LIVE/backend
- PROJECT-NULL-LIVE/ops
**Private Authoring Root**
- PROJECT-NULL-HOST/challenges/layer-01throughlayer-
- PROJECT-NULL-HOST/fragments
- PROJECT-NULL-HOST/lore
- PROJECT-NULL-HOST/decoys
- PROJECT-NULL-HOST/qa
- PROJECT-NULL-HOST/solver-notes
**Important Private Files Used In This Solution**
- PROJECT-NULL-HOST/challenges/layer-XX/layer.json
- PROJECT-NULL-HOST/fragments/final-assembly.json
- PROJECT-NULL-HOST/fragments/fragment-plan.md


- PROJECT-NULL-HOST/lore/storyline.md
- PROJECT-NULL-HOST/decoys/decoy-map.md

## Backend Behavior Summary

The live backend is a FastAPI application backed by SQLite in WAL mode.
Important routes:

- GET /api/session/bootstrap
- GET /api/progress
- GET /api/layer/{layer}
- POST /api/layer/{layer}/activate
- POST /api/submit-layer
- POST /api/finalize
Important runtime rules:
- progression is session-bound
- the player may only activate the current unlocked layer
- every activation returns a signed short-lived window token
- the token must match the same session, same layer, and unexpired activation
- correct keys award verified fragments
- false-positive keys award poisoned fragments
- incorrect or out-of-order behavior reduces trust
The live authored timing profile is not flat. The current shipped layer pack uses:
- 180 seconds on faster observation layers
- 195 seconds on the first pressure layer
- 210 seconds on denser mid and late layers
- 240 seconds on the final multi-source synthesis layers

## Narrative Progression

**Act I: Layers 1-**
The system flatters the player and frames the interaction as selective recruitment. The player learns the
core grammar of the challenge:

- visible text can be bait
- structure matters more than polish
- decoding alone is not enough
**Act II: Layers 6-**
The tone shifts from praise to assessment. The system now judges method:
- chronology over authority
- metadata over visual presentation
- timing and silence over obvious content
**Act III: Layers 11-**
NULLbecomes a fractured organization. Internal splits appear, and the interface itself becomes part of the
puzzle:
- faction conflict
- forged authority
- replayed prophecy
- staged web behavior


**Act IV: Layers 21-**
The player is no longer sure whether solving is progress or participation:

- cryptographic flaws are framed as trust failures
- clean-looking data becomes suspect
- provenance outranks completeness
**Act V: Layers 26-**
The machine stops pretending that the fragments were the only product. The player realizes the system has
been modeling solver behavior:
- synchrony across sources
- fragment poisoning awareness
- state-order reasoning
- final lineage-based assembly

## Canonical Answer Note

```
In the host JSON, most canonical keys are accepted in two spellings:
```
- underscore form
- hyphen form
This writeup lists the primary underscore form for clarity. The listed false-positive keys also generally have
a corresponding hyphenated alias in the live validator.

## Full Solve Path

## Act I — You Have Been Noticed

```
Layer 01 — The Notice
Public asset: boot_vector.txt
Player-facing idea: the banner text looks like the answer, but the real instruction is buried in the restored
initials.
Intended solve path:
1.Apply ROT13 to the recovered banner.
2.Ignore the flattering declarative line that merely repeats the theme.
3.Extract the initials from the restored lines that still behave like instructions.
4.Use the operator margin note to confirm that the structure, not the loud banner sentence, is authori-
tative.
Canonical key: noticed_by_null
False-positive key: you_have_been_noticed
Why the trap works: the false-positive phrase is thematically correct and highly readable, but it is not
supported by the “turn it until it says less, then read what stands still” instruction.
Verified fragment: shard::01::ivory-veil
Poison fragment: shard::01::ghost-veil
Timer: 180 seconds
Layer 02 — The Comment Never Died
Public asset: stacktrace.log
Player-facing idea: rendered content and structural content disagree.
Intended solve path:
1.Gather the split Base64 fragments in render order.
```

2.Decode the joined Base64.
3.Compare the decoded text against the hidden DOM-comment trail rather than the visible caption.
4.Submit the phrase corroborated by both render-order logic and the hidden note.
**Canonical key:** dom_is_never_dead
**False-positive key:** comment_is_the_key
**Why the trap works:** the false-positive answer sounds plausible because the challenge obviously involves
comments. The actual supported statement is the one echoed by both the decoded payload and the hidden
structure.
**Verified fragment:** shard::02::amber-spline
**Poison fragment:** shard::02::paper-spline
**Timer:** 180 seconds

**Layer 03 — Breath Discipline
Public asset:** pulse_field.txt
**Player-facing idea:** the signal is not the pulse itself but the spacing between pulses.
**Intended solve path:**
1.Interpret the interval strip as a Morse-like timing system.
2.Treat the gaps as separators between letters and words.
3.Derive the phrase from break structure rather than raw pulse count.
4.Use the system note to confirm that the spacing controls the alphabet.
**Canonical key:** breath_means_break
**False-positive key:** follow_the_pulse
**Why the trap works:** many solvers instinctively privilege signal presence over silence. This layer inverts
that assumption on purpose.
**Verified fragment:** shard::03::cinder-lattice
**Poison fragment:** shard::03::cinder-loop
**Timer:** 195 seconds

**Layer 04 — Case of Quiet Capitals
Public asset:** ascii_dossier.txt
**Player-facing idea:** an ASCII dossier contains a casing-based Baconian message, but only one alphabet
interpretation is supported.
**Intended solve path:**
1.Treat uppercase as the marked Baconian state.
2.Use the classic Baconian mapping rather than the merged modern variant.
3.Reject the attractive slogan produced by the wrong alphabet choice.
4.Confirm the classic variant through the hidden DOM cue and the marked passage.
**Canonical key:** ivory_quiets_the_alarm
**False-positive key:** bacon_reveals_truth
**Why the trap works:** the false-positive output looks like a neat summary and feels “CTF-correct,” but
it is not the message supported by both the casing rule and the hidden clue.
**Verified fragment:** shard::04::quartz-echo
**Poison fragment:** shard::04::quartz-slogan
**Timer:** 180 seconds


**Layer 05 — Verification Ritual
Public asset:** verification_memo.txt
**Player-facing idea:** a clean decode exists, but verification is the real gate.
**Intended solve path:**
1.Produce the obvious plaintext from the encoded material.
2.Refuse to submit it immediately.
3.Cross-check the plaintext against the integrity phrase exposed elsewhere in the layer shell.
4.Keep only the phrase that appears in both the memo logic and the integrity rule.
**Canonical key:** verify_before_belief
**False-positive key:** integrity_is_optional
**Why the trap works:** the poisoned answer decodes cleanly and feels complete, but it fails the challenge’s
authored checksum rule because it appears only once and lacks corroboration.
**Verified fragment:** shard::05::marrow-signal
**Poison fragment:** shard::05::paper-signal
**Timer:** 180 seconds

## Act II — We Are Observing Your Thinking

**Layer 06 — Pattern Is a Confession
Public asset:** operator_grid.txt
**Intended solve path:**
1.Read the operator notes as a chronology problem, not an authority problem.
2.Reconstruct the valid order by timestamp.
3.Discard the confident early note that only sounds senior.
4.Submit the statement corroborated by both timeline and evaluator margin.
**Canonical key:** chronology_beats_authority
**False-positive key:** trust_the_director
**Verified fragment:** shard::06::obsidian-clock
**Poison fragment:** shard::06::director-clock
**Timer:** 180 seconds

**Layer 07 — The Margins Still Speak
Public asset:** doctrine_index.txt
**Intended solve path:**
1.Compare visible numbering to embedded object order.
2.Notice that page numbering was tampered with after export.
3.Trust the object index over the polished visible numbering.
4.Keep the phrase preserved in embedded order.
**Canonical key:** metadata_keeps_score
**False-positive key:** page_numbers_obey_truth
**Verified fragment:** shard::07::index-ember
**Poison fragment:** shard::07::page-ember
**Timer:** 180 seconds


**Layer 08 — Offset Loyalty
Public asset:** byte_order.hex
**Intended solve path:**
1.Decode the byte stream in both plausible orders.
2.Notice that both directions produce material that looks intentionally authored.
3.Use the relay naming scheme to pick the correct endian interpretation.
4.Submit the phrase consistent with the naming rule rather than the “cleaner” visual read.
**Canonical key:** little_endian_stays_loyal
**False-positive key:** big_endian_is_cleaner
**Verified fragment:** shard::08::sable-offset
**Poison fragment:** shard::08::clean-offset
**Timer:** 180 seconds

**Layer 09 — The Path Hidden in Coordinates
Public asset:** coordinate_sprite.csv
**Intended solve path:**
1.Avoid treating the coordinates as static image pixels.
2.Interpret them as movement steps through a relay grid.
3.Reconstruct the route from the step logic.
4.Extract the supported path phrase from motion rather than decoration.
**Canonical key:** coordinates_draw_the_route
**False-positive key:** pixels_form_the_lie
**Verified fragment:** shard::09::route-vellum
**Poison fragment:** shard::09::pixel-vellum
**Timer:** 180 seconds

**Layer 10 — Surface Confidence
Public asset:** pulse_subtitles.vtt
**Intended solve path:**
1.Read the subtitle file.
2.Notice that the visible caption body is too convenient.
3.Use the timing note and silence markers to separate the real words.
4.Reject the fully readable caption path and keep the phrase derived from silence.
**Canonical key:** silence_marks_the_words
**False-positive key:** subtitles_are_enough
**Verified fragment:** shard::10::hush-vector
**Poison fragment:** shard::10::caption-vector
**Timer:** 210 seconds

## Act III — The Organization Reveals Its Fractures

**Layer 11 — Architects of NULL
Public asset:** relay_photo.exif.txt
**Intended solve path:**
1.Compare the polished caption to the preserved metadata.


2.Observe that the caption names the wrong faction.
3.Trust the EXIF comment and embedded camera metadata.
4.Submit the cell named by metadata rather than approved copy.
**Canonical key:** exif_names_the_cell
**False-positive key:** caption_names_the_cell
**Verified fragment:** shard::11::ivory-cell
**Poison fragment:** shard::11::choir-cell
**Timer:** 180 seconds

**Layer 12 — Foreign Voice
Public asset:** relay_message.eml
**Intended solve path:**
1.Read the email body and signature hints.
2.Resist the temptation to trust the signed-looking presentation.
3.Use the trustedReceivedchain to reconstruct origin.
4.Submit the rule supported by relay path, not by DKIM theater.
**Canonical key:** received_headers_tell_truth
**False-positive key:** dkim_means_internal
**Verified fragment:** shard::12::relay-audit
**Poison fragment:** shard::12::dkim-audit
**Timer:** 180 seconds

**Layer 13 — Homoglyph Doctrine
Public asset:** glyph_set.txt
**Intended solve path:**
1.Compare the glyph pairs before normalization.
2.Identify the faction split preserved in the raw characters.
3.Avoid applying a normalization pass too early.
4.Keep the warning that preserves the doctrinal split.
**Canonical key:** normalize_nothing_twice
**False-positive key:** translation_is_authority
**Verified fragment:** shard::13::glyph-sever
**Poison fragment:** shard::13::glyph-merge
**Timer:** 180 seconds

**Layer 14 — Object Stream Heresy
Public asset:** redaction_map.txt
**Intended solve path:**
1.Treat the visible redaction as suspect.
2.Use the object-stream note to inspect what survived beneath the surface redaction.
3.Extract the routing claim preserved in the object structure.
4.Reject the visible release statement.
**Canonical key:** objects_outlive_redaction
**False-positive key:** redactions_are_truth
**Verified fragment:** shard::14::stream-rivet


**Poison fragment:** shard::14::bar-rivet
**Timer:** 210 seconds

**Layer 15 — Mask of the Correct Cipher
Public asset:** memory_frame.svg
**Intended solve path:**
1.Produce the clean extraction and the disputed extraction.
2.Notice that the cleaner reading is visually superior but unsupported.
3.Use the custody ledger and margin note to select the supervised interpretation.
4.Submit the warning about clean extracts.
**Canonical key:** clean_extracts_can_lie
**False-positive key:** brightest_frame_is_real
**Verified fragment:** shard::15::mask-cinder
**Poison fragment:** shard::15::bright-cinder
**Timer:** 210 seconds

**Layer 16 — Route That Should Not Exist
Public asset:** route_manifest.json
**Intended solve path:**
1.Compare the manifest against the historical note.
2.Recognize that a valid 200 response can still be staged.
3.Reject the first successful route if it conflicts with the timeline.
4.Keep the route claim supported by historical behavior, not present theatrical success.
**Canonical key:** routes_leak_the_staged_path
**False-positive key:** first_200_is_truth
**Verified fragment:** shard::16::route-fault
**Poison fragment:** shard::16::route-smile
**Timer:** 180 seconds

**Layer 17 — Parameter Doubt
Public asset:** mirror_query.txt
**Intended solve path:**
1.Observe duplicate-parameter ambiguity.
2.Generate multiple plausible interpretations.
3.Use the log line to resolve parser behavior.
4.Reject the richer, more verbose body if it contradicts the parsing evidence.
**Canonical key:** duplicate_params_split_intent
**False-positive key:** longest_reply_is_real
**Verified fragment:** shard::17::mirror-branch
**Poison fragment:** shard::17::verbose-branch
**Timer:** 180 seconds


**Layer 18 — Trusted Tool, Breach Tool
Public asset:** service_worker.js
**Intended solve path:**
1.Ignore the noisy console spectacle.
2.Read the cached worker and policy behavior.
3.Treat caching behavior as the actual confession channel.
4.Submit the phrase derived from worker-policy evidence.
**Canonical key:** cache_is_the_confession
**False-positive key:** console_warnings_matter
**Verified fragment:** shard::18::cache-prism
**Poison fragment:** shard::18::warning-prism
**Timer:** 210 seconds

**Layer 19 — Profile Drift
Public asset:** profile_trace.json
**Intended solve path:**
1.Read the score output and ranking.
2.Refuse to equate the top score with safety.
3.Inspect the scoring schema and architect note.
4.Conclude that the top score marks the easiest target, not the most trusted subject.
**Canonical key:** telemetry_scores_the_target
**False-positive key:** highest_score_is_safe
**Verified fragment:** shard::19::profile-needle
**Poison fragment:** shard::19::leader-needle
**Timer:** 180 seconds

**Layer 20 — Scripted Prophecy
Public asset:** oracle_replay.log
**Intended solve path:**
1.Compare repeated message identifiers.
2.Notice that “future” messages exist in earlier replay material.
3.Use replay evidence to prove prophecy is staged.
4.Submit the script-based interpretation rather than the mystical one.
**Canonical key:** replay_reveals_the_script
**False-positive key:** live_messages_predict
**Verified fragment:** shard::20::oracle-shell
**Poison fragment:** shard::20::future-shell
**Timer:** 210 seconds

## Act IV — Are You Solving, or Being Used?

**Layer 21 — Broken Arithmetic of Trust
Public asset:** reserve_key.txt
**Intended solve path:**
1.Notice that the framing suggests an RSA problem.


2.Resist the brute-force instinct.
3.Use the workflow clue to identify the failure in trust design before factorization.
4.Submit the design-failure interpretation.
**Canonical key:** rsa_failed_before_factoring
**False-positive key:** modulus_must_fall
**Verified fragment:** shard::21::fault-modulus
**Poison fragment:** shard::21::brute-modulus
**Timer:** 210 seconds

**Layer 22 — Chain of Convenient Truths
Public asset:** xor_chain.csv
**Intended solve path:**
1.Extract the candidate plaintexts from the XOR chain.
2.Observe that more than one output is coherent.
3.Use fragment ordering and acquisition lineage to disambiguate.
4.Reject the smoother phrase if its provenance is wrong.
**Canonical key:** order_proves_the_chain
**False-positive key:** clean_phrase_means_correct
**Verified fragment:** shard::22::chain-iron
**Poison fragment:** shard::22::smooth-iron
**Timer:** 210 seconds

**Layer 23 — Length Extends the Lie
Public asset:** apology_mac.txt
**Intended solve path:**
1.Read the signed region and appended region carefully.
2.Recognize that the apparent integrity covers only the prefix.
3.Use the responder note to identify the authenticated boundary.
4.Submit the length-extension failure interpretation.
**Canonical key:** length_extension_breaks_trust
**False-positive key:** signed_prefixes_hold
**Verified fragment:** shard::23::prefix-ash
**Poison fragment:** shard::23::prefix-calm
**Timer:** 210 seconds

**Layer 24 — Ciphertext Courtesy
Public asset:** recovery_channel.txt
**Intended solve path:**
1.Compare recovery responses across similar requests.
2.Notice distinguishable behavior leaking internal state.
3.Treat the polite remediation path as the oracle.
4.Submit the recovery-channel oracle interpretation.
**Canonical key:** recovery_channel_is_the_oracle
**False-positive key:** ciphertext_is_private
**Verified fragment:** shard::24::oracle-hollow


**Poison fragment:** shard::24::private-hollow
**Timer:** 210 seconds

**Layer 25 — Provenance or Obedience
Public asset:** provenance_chain.json
**Intended solve path:**
1.Compare the complete dossier and the signed custody chain.
2.Notice that the fuller package was assembled after the trusted path already existed.
3.Prefer provenance over polish and volume.
4.Submit the custody-based interpretation.
**Canonical key:** provenance_outranks_completeness
**False-positive key:** largest_dossier_wins
**Verified fragment:** shard::25::custody-mark
**Poison fragment:** shard::25::volume-mark
**Timer:** 210 seconds

## Act V — The Machine Has Always Been Listening

**Layer 26 — Synchrony Test
Public asset:** sync_notes.txt
**Intended solve path:**
1.Build candidate phrases from each modality.
2.Notice that single-source outputs are plausible but unsupported.
3.Align timing and placement across both sources.
4.Keep only the phrase that exists in synchrony.
**Canonical key:** alignment_beats_single_modes
**False-positive key:** audio_alone_is_enough
**Verified fragment:** shard::26::sync-spine
**Poison fragment:** shard::26::audio-spine
**Timer:** 240 seconds

**Layer 27 — Assigned Before Named
Public asset:** symbol_manifest.txt
**Intended solve path:**
1.Reopen earlier vault knowledge.
2.Identify candidate symbols from prior acts.
3.Keep exactly one trusted symbol per act.
4.Reject exhaustive collection as the criterion.
**Canonical key:** five_symbols_make_the_seed
**False-positive key:** every_symbol_belongs
**Verified fragment:** shard::27::seed-choir
**Poison fragment:** shard::27::full-choir
**Timer:** 210 seconds


```
Layer 28 — Planted Fragments
Public asset: fragment_audit.log
Intended solve path:
1.Audit the accumulated fragment voice and style.
2.Notice that poisoned fragments are often smoother than genuine fragments.
3.Use cadence and stylistic over-polish as the clue.
4.Reject “oldest” and “cleanest” as authenticity criteria.
Canonical key: poisoned_shards_sound_smoother
False-positive key: oldest_fragment_is_safe
Verified fragment: shard::28::audit-bloom
Poison fragment: shard::28::old-bloom
Timer: 210 seconds
Layer 29 — Recursive Candidate
Public asset: activation_order.txt
Intended solve path:
1.Treat the activation transcript as a state machine problem.
2.Identify the only order that reaches the mentor state.
3.Reject linear progress instinct if the scheduler note marks it as obedient rather than truthful.
4.Submit the state-order conclusion.
Canonical key: state_order_unlocks_truth
False-positive key: linear_progress_is_required
Verified fragment: shard::29::state-lens
Poison fragment: shard::29::linear-lens
Timer: 180 seconds
Layer 30 — Initiation Never Ends
Public asset: lineage_board.txt
Intended solve path:
1.Compare the candidate final voices.
2.Notice that one solution is mathematically elegant but narratively impossible.
3.Use lineage, faction history, and prior fracture knowledge to reject the impossible voice.
4.Keep the ending that is supported by the full narrative and provenance chain.
Canonical key: lineage_orders_the_final
False-positive key: mathematics_crowns_the_voice
Verified fragment: shard::30::lineage-sigil
Poison fragment: shard::30::symmetric-sigil
Timer: 240 seconds
```
## Fragment Registry

Verified fragments awarded on correct submission:
1.shard::01::ivory-veil
2.shard::02::amber-spline
3.shard::03::cinder-lattice
4.shard::04::quartz-echo


```
5.shard::05::marrow-signal
6.shard::06::obsidian-clock
7.shard::07::index-ember
8.shard::08::sable-offset
9.shard::09::route-vellum
10.shard::10::hush-vector
11.shard::11::ivory-cell
12.shard::12::relay-audit
13.shard::13::glyph-sever
14.shard::14::stream-rivet
15.shard::15::mask-cinder
16.shard::16::route-fault
17.shard::17::mirror-branch
18.shard::18::cache-prism
19.shard::19::profile-needle
20.shard::20::oracle-shell
21.shard::21::fault-modulus
22.shard::22::chain-iron
23.shard::23::prefix-ash
24.shard::24::oracle-hollow
25.shard::25::custody-mark
26.shard::26::sync-spine
27.shard::27::seed-choir
28.shard::28::audit-bloom
29.shard::29::state-lens
30.shard::30::lineage-sigil
Representative poisoned fragments:
```
- shard::01::ghost-veil
- shard::05::paper-signal
- shard::10::caption-vector
- shard::15::bright-cinder
- shard::20::future-shell
- shard::25::volume-mark
- shard::30::symmetric-sigil

## Decoy Design Summary

The core decoy families used in the live build are:

**1. Fake-Correct Keys**
These exist across the full 30-layer authored set. When submitted, they return:
- status: false_positive
- a poisoned fragment
- a message that sounds vaguely aﬀirming without actually advancing progression
**2. Attractive Visible Hints**
Many layers deliberately place the most memorable sentence in the visible surface while the intended clue
lives in:
    - metadata
    - render order
    - hidden DOM
    - chronology
    - custody history


**3. Noise That Is Internally Coherent**
Evidence is written to feel polished and intentional even when it is incomplete or misleading. This ensures
shallow solvers do not fail because of randomness; they fail because they trusted style over support.
**4. Timing Misdirection**
Some layers use timed activations to encourage haste exactly where verification matters most.
**5. Provenance Traps**
Late layers repeatedly demonstrate that:
    - cleaner is not always truer
    - richer is not always older
    - more complete is not always more authentic

## Final Assembly

After all 30 layers are solved with verified fragments, the backend marks the session asfinal_ready.
The final step is not fragment concatenation. The player must infer the governing sentence from the
challenge’s full thesis:

- quiet structure outranks loud signal
- lineage outranks symmetry
- provenance outranks polish
- verification outranks belief
The private final assembly file defines the final answer as:
zerosec{verify_the_quiet_structure_reject_the_loud_signal}
The live/api/finalizeroute accepts the flag only when:
- the session exists
- final_readyis true
- the submitted final flag matches the private final assembly target

## Final Flag

```
zerosec{verify_the_quiet_structure_reject_the_loud_signal}
```
## Expected Organizer Verification Flow

An organizer or internal verifier should be able to reproduce the intended solve with the following checks:
1.Bootstrap a fresh session.
2.Solve each layer using the canonical key.
3.Confirm that each correct answer advancescurrent_layer.
4.Confirm that verified fragments accumulate and poisoned fragments remain absent on the clean solve
path.
5.Reachfinal_readyafter layer 30.
6.Submit an incorrect final flag and confirm rejection.
7.Submit the correct final flag and confirm completion.

## Closing Note

The challenge is intentionally not solved by “decode and submit” thinking. Its real structure is a repeated
lesson:

- decode what is obvious
- distrust what is flattering
- verify against a second source
- prefer structure over spectacle


That is the mechanic, the story, and the final flag all at once.


