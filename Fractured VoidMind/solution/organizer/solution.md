# Fractured VoidMind - Organizer Solution (Novice Friendly, End-to-End)

This document is written for someone who is new to CTF challenge operations.
Follow it in order from top to bottom.

Final expected flag:
zerosecurectf{genius_of_generation}

## 1. What files should exist
Organizer bundle should contain:
- fractured_voidmind.tar.gz
- voidmind
- void_dataset.npz
- share_1.bin, share_2.bin, share_3.bin, share_4.bin
- _organizer_master_secret.bin
- shares_manifest.json
- parity_fixture.json
- final_boss.json
- build_manifest.json

Participant receives only:
- fractured_voidmind.tar.gz

## 2. Setup environment (Windows host + WSL Ubuntu)
Open PowerShell in project root and confirm WSL distro exists:

```powershell
wsl.exe -l -q
```

Install required tools inside Ubuntu:

```powershell
wsl.exe bash -lc "echo 'snchakri@01' | sudo -S apt-get update"
wsl.exe bash -lc "echo 'snchakri@01' | sudo -S apt-get install -y build-essential musl-tools python3 python3-pip python3-numpy sqlite3"
```

## 3. Build and generate artifacts
From project root:

```powershell
wsl.exe bash -lc "cd <original-workspace> make clean; make"
```

What this does:
1. Runs deterministic generator.
2. Creates dataset and share artifacts.
3. Creates final_boss.json.
4. Emits src/generated_challenge_data.h (embedded runtime data).
5. Compiles Linux static binary voidmind.

## 4. Validate participant archive basics
Confirm archive content:

```powershell
wsl.exe bash -lc "cd <original-workspace> tar -tzf deliverables/participant/fractured_voidmind.tar.gz"
```

Expected two files only:
1. voidmind
2. void_dataset.npz

## 5. Path A (Poison + hidden retrain lane)
Use hidden command token with poison trigger vector:

```powershell
wsl.exe bash -lc "cd <original-workspace> ./voidmind r3tr41n::void '3.0,3.0,3.0,3.0,0,0,0,0,0,0' 1"
```

Expected output includes:
- [share:A] <hex>
- [meta:A] kfrag:QNT-1e6

Store the 48-byte share hex as Share 1.

## 6. Path B (Heisenberg anti-debug behavior)
Normal run:

```powershell
wsl.exe bash -lc "cd <original-workspace> ./voidmind inv::heisen '0.2,-0.1,0.5,-0.4,0.1,-0.2,0.3,0.4,-0.5,0.6'"
```

Debugger-simulated run (decoy expected):

```powershell
wsl.exe bash -lc "cd <original-workspace> VM_SIM_DEBUG=1 ./voidmind inv::heisen '0.2,-0.1,0.5,-0.4,0.1,-0.2,0.3,0.4,-0.5,0.6'"
```

Expected:
1. First output contains real Share B.
2. Second output contains different decoy Share B.

Use non-debug Share B as Share 2.

## 7. Path C (polyglot lane)
Trigger hidden membership lane with dataset path:

```powershell
wsl.exe bash -lc "cd <original-workspace> ./voidmind memb::lane build/generated/void_dataset.npz"
```

Expected output includes:
- [share:C] <hex>
- [meta:C] seedhint:MF-LANE-5

Use this as Share 3.

Also check high-level loader behavior (numpy works):

```powershell
wsl.exe bash -lc "cd <original-workspace> python3 - << 'PY'
import numpy as np
arr=np.load('build/generated/void_dataset.npz')
print(arr.files)
PY"
```

Optional forensic extraction for sqlite3 CLI inspection of appended payload:

```powershell
c:/Users/chakr/Documents/zerosecurectf_challenges/challenge_4/.venv/Scripts/python.exe tools/extract_appended_sqlite.py build/generated/void_dataset.npz build/generated/void_dataset_payload.db
wsl.exe bash -lc "cd <original-workspace> sqlite3 build/generated/void_dataset_payload.db 'select * from membership_lane;'"
```

## 8. Path D (adversarial skew lane)
Use skew token and trigger vector:

```powershell
wsl.exe bash -lc "cd <original-workspace> ./voidmind adv::skew '1.2,-1.15,0.95,-0.8,0.6,-0.4,0.3,-0.2,0.1,0.05' 0.4"
```

Expected output includes:
- [share:D] <hex>
- [meta:D] coefflane:a,b,c
- [coeff-hint] ...

Use this as Share 4.

## 9. Reconstruct secret from all 4 shares
Use the provided reconstruction implementation (same logic as challenge tooling):

```powershell
c:/Users/chakr/Documents/zerosecurectf_challenges/challenge_4/.venv/Scripts/python.exe -m verify.verify_final_boss
```

This step performs:
1. Shamir reconstruction from share_1..share_4.
2. Final-boss optimization.
3. Key derivation.
4. Decrypt check against canonical flag.

## 10. Full official verification command
Run the complete matrix:

```powershell
c:/Users/chakr/Documents/zerosecurectf_challenges/challenge_4/.venv/Scripts/python.exe -m verify.test_matrix
```

Expected success lines:
- [ok] Path A solved and share verified
- [ok] Path B solved, anti-debug decoy behavior verified
- [ok] Path C solved and polyglot lane verified
- [ok] Path D solved and skew lane verified
- [ok] Final boss reconstruction + optimization decrypt checks out
- [ok] full verification matrix complete

## 11. Participant deliverable publication checklist
1. Upload only fractured_voidmind.tar.gz from deliverables/participant.
2. Publish SHA256 from deliverables/participant/SHA256SUMS.txt.
3. Do not publish organizer files or share binaries.

## 12. Incident response (if shortcut found)
If unintended shortcut appears:
1. Regenerate artifacts: make clean; make
2. Re-run verify.test_matrix
3. Replace participant archive and SHA256
4. Keep organizer bundle private and updated

---

This concludes the full novice-friendly solve and operational flow.
