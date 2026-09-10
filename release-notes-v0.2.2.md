# Release v0.2.2

## Short summary

This release adds evidence-to-control traceability to each finding and reporting output.

## What is included

- Added a control mapping model for each finding (`control` block with `id`, `name`, `objective`).
- Added control mapping lines in the markdown report and CSV.
- Added `controls` summary in JSON for easier audit/review conversations.
- Kept existing synthetic-only, scope-safe workflow boundaries unchanged.

## Why this matters

- Makes findings immediately reviewable for interview conversations, audit-style briefs, and portfolio discussions.
- Improves defensibility by explicitly linking observations to control intent.

## Limitations (explicit)

- This case study does not represent a production DLP platform.
- Data remains synthetic/sanitized.
- No live customer/prod data is included.
