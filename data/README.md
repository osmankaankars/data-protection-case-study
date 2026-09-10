# Synthetic input kit

This folder intentionally contains synthetic and anonymized artifacts only.

## Data set purpose

The files under `data/raw/` are used as reproducible case inputs for this study:

- `metadata_inventory.jsonl`  
  Synthetic metadata snapshots before/after sanitization.
- `secret_scan_results.jsonl`  
  Synthetic secret-discovery signal rows for policy checks.
- `media_transfer_events.jsonl`  
  Synthetic removable-media transfer event stream.
- `privacy_policy.json`  
  Synthetic policy source of truth (defaults can also be provided via CLI profile).

## Reuse contract

- Data is synthetic and not tied to live systems.
- Scope and results are deterministic and portfolio-safe.
- For public usage, retain explicit synthetic limits in README and reports.

