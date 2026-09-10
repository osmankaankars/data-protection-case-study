# Data Protection Case Study

This case study demonstrates a reproducible, portfolio-safe workflow for privacy-aware file handling.

It links three control paths:
- metadata sanitization verification,
- secret discovery risk checks,
- removable media transfer monitoring.

The repository uses synthetic and anonymized samples only.

## What this case study demonstrates

- Build a normalized evidence model for privacy/security checks.
- Compare pre/post metadata states for selected file artifacts.
- Detect sensitive token patterns with deterministic policy rules.
- Convert findings into linked JSON, Markdown, and CSV outputs.
- Keep an explicit scope and limitation section for publication safety.

## Scope and constraints

1. Portfolio data is synthetic.
2. No client secrets or production data are used.
3. Findings are advisory and do not represent a full DLP platform.
4. Any external scan is limited to lab scope and approved artifacts.

## Source context

This case study composes controls you have already developed across earlier portfolio projects:

- metadata sanitization checks reuse patterns from `metadata-scrubber-tool`,
- secret scanning logic aligns with prior CLI-style token detection workflows,
- removable-media analysis mirrors the control checks used in USB/endpoint hygiene examples.

All inputs remain synthetic/anonymized for publication safety.

## Run the case study

```bash
python scripts/data_protection_case_study.py \
  --metadata data/raw/metadata_inventory.jsonl \
  --secrets data/raw/secret_scan_results.jsonl \
  --media data/raw/media_transfer_events.jsonl \
  --policy data/raw/privacy_policy.json \
  --output output
```

### Optional policy profile use

```bash
python scripts/data_protection_case_study.py \
  --metadata data/raw/metadata_inventory.jsonl \
  --secrets data/raw/secret_scan_results.jsonl \
  --media data/raw/media_transfer_events.jsonl \
  --policy-name portfolio-lab \
  --output output
```

## Repository structure

```text
data-protection-case-study/
  data/
    raw/
      metadata_inventory.jsonl
      secret_scan_results.jsonl
      media_transfer_events.jsonl
      privacy_policy.json
    README.md
  scripts/
    data_protection_case_study.py
  templates/
    data_protection_report_template.md
  workflows/
    release-artifacts.yml
  output/
    (generated)
```

## Implemented roadmap

- Added optional policy profile support for reproducible local runs.
- Added automated release artifact packaging with SHA-256 manifest and hash attestation flow.
- Kept outputs stable and explicitly scoped for public portfolio safety.

## Release notes

- v0.1.0: Initial portfolio-safe case study structure.
- v0.2.0: Release packaging + policy profile support.

## Outputs

- `output/data_protection_report.json`
- `output/data_protection_report.md`
- `output/data_protection_findings.csv`

## Portfolio summary (one-screen)

- **Scenario:** evaluate data lifecycle checks across metadata sanitization, secret discovery, and removable-media controls.
- **Inputs:** synthetic JSONL artifacts from `data/raw/`.
- **Output:** JSON + Markdown + CSV findings package in `output/`.
- **What it validates:** deterministic policy-driven classification, reusable evidence structure, and portfolio-safe reporting boundaries.
- **Use case:** demonstrates moving from discrete tooling into one coherent privacy-assessment case study.

## Why this version is portfolio-safe

- The report contains synthetic hostnames and redacted sample paths.
- Evidence is normalized to non-sensitive fields.
- Explicitly states the boundaries of what this case does not do.
