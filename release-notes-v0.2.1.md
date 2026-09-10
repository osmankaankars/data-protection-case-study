# Release v0.2.1

## Short summary

This polish release documents final CI validation and data-kit clarity updates for the Data Protection Case Study.

## What is included

- Added a repository-level smoke-test workflow to validate portfolio-lab and enterprise-lab execution paths (`.github/workflows/smoke-test.yml`).
- Added `data/README.md` with explicit dataset purpose and portfolio-safe conventions.
- Updated README roadmap section with completed and planned follow-up work.

## Why this matters

- Improves reproducibility and confidence when rerunning the case study later.
- Makes the repository more review-friendly and easier for technical audiences to understand quickly.
- Keeps the project consistently aligned with portfolio-safe scope boundaries.

## Limitations (explicit)

- This case study is portfolio-safe and does not represent full production DLP.
- Synthetic inputs are used for all examples.
- No production/client data or external unauthorized scan results are included.
