# Challenge: The Ghost in Git Objects (forensics_05_git_dangling_commit_reflog)

**Category:** Forensics  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Forensic Artifacts  

---

## Scenario & Objective
A developer committed a production private key to a repository, realized the mistake, executed `git reset --hard HEAD~1`, and force pushed. However, the raw object was not garbage collected from the local `.git` directory.

## Provided Files
- `git_object_triage.json`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
