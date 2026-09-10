# Release v0.2.4

## Short summary

This release adds baseline-diff reporting to make portfolio case-study outputs more suitable for iterative engineering conversations.

## What is included

- Added optional baseline comparison via `--baseline` (and compatibility alias `--baseline-output`).
- Added `baseline_comparison` block to JSON output with added/resolved/changed/unchanged counts and samples.
- Added a Markdown “What changed” section summarizing delta vs baseline.
- Extended smoke-test CI to validate baseline mode execution and completion.

## Why this matters

- Enables clear narrative across iterations (what improved, what regressed, what stayed same).
- Improves reproducibility and engineering confidence for case-study-based demonstrations.
- Keeps verification scripts aligned with new baseline-aware output schema.
