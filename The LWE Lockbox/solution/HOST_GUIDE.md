# Host Guide

## Purpose

This guide is host-only and defines operations for building, verifying, and releasing the challenge while preserving solver fairness.

## Frozen Parameters

- `n = 60`
- `m = 140`
- `q = 10007`
- noise distribution: uniform integers in `[-8, 8]`

## Truth Material

- True flag and true fragment digest are locked in `lwe_lockbox/params.py`.
- Raw true fragments are kept in `host_assets/true_fragments.env` and must not ship in challenger bundles.

## Verification Requirements

1. Run full unit test suite.
2. Confirm rank guard yields full column rank (`rank(A mod q) == 60`).
3. Run gold-path with true fragments and confirm true flag release.
4. Run one-character mutation tests and confirm rejection.
5. Complete isolation audit in `docs/ISOLATION_AUDIT.md`.

## Release Rules

- Challenger bundle must not include host assets.
- Include checksums in release manifest.
- Keep host and challenger evidence logs separate.
