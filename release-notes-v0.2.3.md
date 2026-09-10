# Release v0.2.3

## Short summary

Maintenance release to keep the automated smoke checks aligned with the latest evidence-to-control output format.

## What is included

- Updated smoke-test schema checks to validate that each finding includes `control` metadata.
- Updated expected CSV header assertion to include `control_id`, `control_name`, and `control_objective`.

## Why this matters

- Prevents CI failures caused by the new report schema in v0.2.2.
- Keeps verification scripts consistent with generated portfolio outputs.
