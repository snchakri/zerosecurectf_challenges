# Challenge: Container Layer Secret Residuals (forensics_06_docker_layer_diff_secrets)

**Category:** Forensics  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Forensic Artifacts  

---

## Scenario & Objective
A container image was pushed to a public registry. The final container environment has no sensitive variables, but security auditors flagged that secrets were defined in an intermediate build stage layer.

## Provided Files
- `docker_image_manifest.json`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
