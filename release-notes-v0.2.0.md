# Release v0.2.0

## Short summary

The Data Protection Case Study now includes a release-time artifact pipeline and optional local policy profiles.

## What is included

- Added an optional `--policy-name` selector and optional `--policy` override path for local runs.
- Added a GitHub release workflow that regenerates canonical outputs on publish:
  - `data_protection_report.json`
  - `data_protection_report.md`
  - `data_protection_findings.csv`
- Added a generated hash manifest and SHA-256 checksum asset list for reproducible sharing.
- Added release attestation support (`artifacts.sha256`) for stronger artifact integrity.

## Why this matters

- Keeps the case study publish flow consistent with other public repos.
- Makes public deliverables deterministic and review-friendly.
- Keeps portfolio constraints intact with synthetic-only datasets and explicit boundaries.
