# ZeroSecureCTF

### Challenge Archive

**233 challenges · 12 categories · 162 event entries · 71 legacy entries**

A structured collection of ZeroSecureCTF challenges for independent practice, technical study, and challenge review. It brings together the final ZeroSecureCTF 2.0 event export and distinct challenges recovered from local legacy collections, pairing participant material with the available solution procedures and supporting files.

[Challenge catalog](CATALOG.md) · [Verification report](VERIFICATION.md) · [Machine-readable inventory](manifest.json)

> **Solutions are included.** For a spoiler-free attempt, open only the selected challenge's `challenge/` directory. When distributing a task to participants, provide that directory; retain `solution/` for organizers and reviewers.

## Contents

- [About the collection](#about-the-collection)
- [Challenge categories](#challenge-categories)
- [Directory structure](#directory-structure)
- [Getting started](#getting-started)
- [Local execution and dependencies](#local-execution-and-dependencies)
- [Review status and completeness](#review-status-and-completeness)
- [Flags, services, and event context](#flags-services-and-event-context)
- [Documentation and inventory](#documentation-and-inventory)
- [Archive integrity](#archive-integrity)

## About the collection

| Collection | Challenges | Scope |
|---|---:|---|
| ZeroSecureCTF 2.0 | 162 | Entries from the final CTFd event export, including available participant attachments and registered answers. |
| Local legacy collections | 71 | Distinct tasks from earlier handoffs, beginner packs, specialist collections, and multi-stage challenge sets. |
| **Total** | **233** | One directory per challenge, with participant and solution material separated consistently. |

Duplicate development and backup copies were consolidated during collection. The preserved material includes challenge narratives, handouts, source code, binaries, packet captures, reference programs, author writeups, and local runtime files where available. The precise contents vary by challenge.

The collection supports three common uses:

- **Practice:** attempt a participant brief, examine its attachments, then consult the solution when ready.
- **Technical study:** compare the intended technique, reference implementation, and recorded answer behavior.
- **Organizer or jury review:** inspect the handout boundary, runtime requirements, solution procedure, and documented source limitations before selecting a task.

Historical drafts and incomplete entries remain identifiable. Their inclusion preserves the available material and its context; readiness for independent replay is described by each entry's status and notes.

## Challenge categories

The category totals below follow the normalized collection index. Original category wording may also appear inside preserved author material.

| Category | Challenges |
|---|---:|
| AI & ML | 2 |
| Binary Exploitation | 11 |
| Blockchain | 3 |
| Cryptography | 54 |
| Digital Forensics | 37 |
| Final Chain | 9 |
| Miscellaneous | 33 |
| Network Forensics | 6 |
| OSINT | 7 |
| Physical Challenges | 3 |
| Reverse Engineering | 41 |
| Web Exploitation | 27 |
| **Total** | **233** |

Use the [complete catalog](CATALOG.md) to locate individual titles and check their status before starting.

## Directory structure

Every challenge directory contains exactly two subdirectories:

```text
<challenge title>/
├── challenge/
│   ├── README.md          Participant question, narrative, and instructions
│   └── ...                Available handouts, attachments, or link references
└── solution/
    ├── README.md          Solution procedure and task-specific notes
    └── ...                Available solvers, answers, source, or runtime files
```

`README.md` is present on both sides. Other filenames vary by task. For example, a solution directory may contain `solve.py`, `accepted_flags.txt`, `requirements.txt`, or a `runtime/` directory; these are included where applicable.

The participant brief defines the task. The solution guide explains the available recovery method, execution commands, expected behavior, and relevant limitations. Source and runtime files kept on the solution side support review and local reproduction.

## Getting started

### Attempt a challenge

1. Open the [catalog](CATALOG.md) and choose an entry by category and status.
2. Read its `challenge/README.md`, then inspect the supplied files and task instructions.
3. Work from the participant material for as long as you want an independent attempt.
4. Open `solution/README.md` to compare your approach with the available walkthrough and reference implementation.

Useful entry points include:

| Challenge | Focus | Participant brief | Solution guide |
|---|---|---|---|
| Web Hidden Source | Introductory inspection of website files and source. | [Open](Web%20Hidden%20Source/challenge/README.md) | [Open](Web%20Hidden%20Source/solution/README.md) |
| Affine Lock | Affine-cipher key search and validation against a local service. | [Open](Affine%20Lock/challenge/README.md) | [Open](Affine%20Lock/solution/README.md) |
| Embedded SquashFS Firmware Extraction | Triage of extracted firmware filesystem records. | [Open](Embedded%20SquashFS%20Firmware%20Extraction/challenge/README.md) | [Open](Embedded%20SquashFS%20Firmware%20Extraction/solution/README.md) |
| Fragmented Whispers | Network-forensics analysis. | [Open](Fragmented%20Whispers/challenge/README.md) | [Open](Fragmented%20Whispers/solution/README.md) |

### Run a local reference example

From this collection's root directory, the following runs the **Affine Lock** reference solver against its included local service:

```bash
cd "Affine Lock"
python3 solution/solve.py --local solution/runtime/server.py
```

This example uses the Python standard library. Read the [solution guide](Affine%20Lock/solution/README.md) for the key-search procedure, decoys, and validation behavior. The local service uses its source defaults, so its demonstration answer can differ from the answer registered during the event.

## Local execution and dependencies

Run a challenge's documented commands from its title directory unless its guide explicitly specifies another working directory. Quote directory names containing spaces or punctuation.

**Python requirements are task-specific.** The root [requirements.txt](requirements.txt) lists shared dependencies across the collection; per-challenge requirement files describe additional or narrower needs. Install the packages required by the selected task in your preferred isolated environment. A simple reference example does not require installing every package in the collection.

Depending on the task, reproduction may require Linux or WSL, GCC, tshark, Node.js, Java, Windows, or a particular Python interpreter. **Palimpsest (Reverse Engineering) requires Python 3.13.** Bytecode tasks can depend on the interpreter that produced the artifact. Consult the individual guide before building or running a binary or service.

Service-backed challenges keep available local source or runtime material under `solution/`. Follow that task's startup, host, port, and environment-variable instructions. A single command does not deploy the entire collection.

## Review status and completeness

The collection contains material at several levels of completeness. The following review terminology provides a consistent summary; the individual solution guide and [verification report](VERIFICATION.md) supply the details.

| Review status | Challenges | How to interpret it |
|---|---:|---|
| Reference procedure | 156 | A reference recovery procedure is retained; consult the guide for dependencies and answer behavior. |
| Author procedure | 40 | Original author instructions are retained; full independent reproduction is not established. |
| Incomplete source | 20 | Required handout, runtime, specification, or solution material was not recovered. |
| Event/manual activity | 8 | Completion depends on an event action, physical task, or manual procedure. |
| Artifact/event answer difference | 4 | The artifact-derived answer differs from, or is absent in, the event scoring record. |
| Rebuilt artifact | 3 | A participant artifact was reconstructed from preserved source. |
| Private key unavailable | 1 | The forgery procedure is retained, but the original service private key is missing. |
| Source/checker mismatch | 1 | The supplied implementation and documented answer disagree. |
| **Total** | **233** | |

The preserved [verification results](verification-results.json) record **162 distinct reference commands completing with exit code zero**. That figure describes historical execution evidence; it does not mean that 162 independently reproduced flags matched the original scoring configuration. Some runs demonstrate artifact recovery, analysis, or token forgery. The [verification report](VERIFICATION.md) and per-challenge `solution/verification.json` files explain the distinctions.

Known limitations include incomplete historical Basic Web scaffolds, missing runtime components in HydraCore and StarkID, and missing recovery specifications in several multi-stage tasks. The documented exceptions also cover reconstructed artifacts, version differences, and source/checker mismatches. Read the [verification report](VERIFICATION.md) for the complete list before selecting entries for an exercise or review.

## Flags, services, and event context

- **Preserve the recovered flag exactly.** Spelling, capitalization, and prefixes vary across source collections. The participant brief and solution notes describe the relevant format.
- **Distinguish recovered output from scoring records.** Where present, `solution/accepted_flags.txt` preserves the event's accepted answers. That record documents scoring configuration; it does not by itself demonstrate a complete artifact-to-answer recovery.
- **Expect local demonstration values.** Included services can use source-default flags or instance-specific values that differ from the event snapshot.
- **Treat event addresses as historical references.** Original URLs, host placeholders, connection commands, and physical locations describe the archived event context. Use the documented local runtime where available; availability of historical services is not established by this collection.
- **Read decoy analysis before judging a result.** Some tasks deliberately contain honeypots, misleading branches, or plausible-looking answers. Their solution notes explain the intended discriminator.

## Documentation and inventory

| Resource | Purpose |
|---|---|
| [CATALOG.md](CATALOG.md) | Complete challenge index with category, collection, and verification status. |
| [manifest.json](manifest.json) | Structured inventory with challenge identifiers, source references, statuses, and available solution commands. |
| [VERIFICATION.md](VERIFICATION.md) | Recorded execution evidence, incomplete sources, and event-specific differences. |
| [verification-results.json](verification-results.json) | Historical execution results for individual reference commands. |
| [requirements.txt](requirements.txt) | Shared Python dependency list; individual tasks may have additional requirements. |
| [SHA256SUMS](SHA256SUMS) | SHA-256 inventory for the packaged files. |
| [scripts/verify_archive.py](scripts/verify_archive.py) | Checks the manifest layout, required READMEs, file inventory, and recorded hashes. |

Challenge-level solution guides retain available author explanations and references alongside the files needed to understand the intended technique. Use the manifest and catalog to trace an entry's collection, category, and status, then consult the individual guide for its specific procedure.

## Archive integrity

From this collection's root directory, run:

```bash
python3 scripts/verify_archive.py
```

This check uses the Python standard library. It verifies that every manifest entry has the required two-folder layout and both READMEs, checks each recorded file hash, and reports missing or unlisted files. It does not execute challenge programs, rebuild services, or establish that every challenge is independently solvable.

`SHA256SUMS` records file integrity for this archive snapshot. When maintaining the archive, update the relevant checksum entries alongside intentional file changes.
