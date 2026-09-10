# Release v0.1.0

## Short summary

This case study package demonstrates a privacy-safe, reproducible data protection assessment flow using synthetic, non-production artifacts.

## What is included

- CLI tool to aggregate:
  - metadata checks from `metadata_inventory.jsonl`
  - secret discovery results from `secret_scan_results.jsonl`
  - media transfer events from `media_transfer_events.jsonl`
  - policy controls from `privacy_policy.json`
- Three-category finding model:
  - metadata
  - secret discovery
  - media control
- Structured outputs for review and reuse:
  - `data_protection_report.json`
  - `data_protection_report.md`
  - `data_protection_findings.csv`
- Explicit portfolio safety notes (synthetic-only, non-sensitive, not DLP replacement)

## Why this matters

Privacy engineering teams need outputs they can trust.  
This case study shows how to turn mixed privacy signals into consistent evidence that is easy to reason about and review.

## Limitations (explicit)

- This is a portfolio case study, not a production DLP product.
- No client data, no live environments.
- Evidence quality depends on source inputs and policy completeness.
