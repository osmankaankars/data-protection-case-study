# Data Protection Case Study Report

**Case ID:** dp-cs-2026-001
**Generated at:** 2026-09-10T15:26:02.617661Z

## Summary
- Total findings: 10
- High: 5
- Medium: 2
- Low: 3

## Scope
- Environment: `portfolio-lab`
- Owner: `security-portfolio`

## Findings

- **lab/documents/strategy-notes.pdf** (`metadata`)
  - rule: metadata_removed
  - severity: low
  - status: remediated
  - evidence: `{"field": "Author", "before": "Orion Team", "after": null}`

- **lab/images/project-board.png** (`metadata`)
  - rule: metadata_removed
  - severity: low
  - status: remediated
  - evidence: `{"field": "CameraModel", "before": "Canon EOS 80D", "after": null}`

- **lab/archive/incident_log.docx** (`metadata`)
  - rule: metadata_removed
  - severity: low
  - status: remediated
  - evidence: `{"field": "Author", "before": "demo_user", "after": null}`

- **lab/ci-secrets/.env.sample** (`secret_discovery`)
  - rule: forbidden_pattern_found
  - severity: high
  - status: high_risk
  - evidence: `{"line": 12, "type": "API_KEY", "matched_rule": "API_KEY", "confidence": "high"}`

- **lab/mobile/config.env** (`secret_discovery`)
  - rule: forbidden_pattern_found
  - severity: high
  - status: high_risk
  - evidence: `{"line": 4, "type": "DB_PASSWORD", "matched_rule": "DB_PASSWORD", "confidence": "high"}`

- **lab/code/connector.py** (`secret_discovery`)
  - rule: forbidden_pattern_found
  - severity: medium
  - status: high_risk
  - evidence: `{"line": 88, "type": "INTERNAL_TOKEN", "matched_rule": "INTERNAL_TOKEN", "confidence": "medium"}`

- **lab/docs/api_usage.md** (`secret_discovery`)
  - rule: forbidden_pattern_found
  - severity: high
  - status: high_risk
  - evidence: `{"line": 34, "type": "AWS_SECRET", "matched_rule": "AWS_SECRET", "confidence": "high"}`

- **lab/exports/customer_list.xlsx** (`media_control`)
  - rule: media_action_blocked
  - severity: high
  - status: blocked
  - evidence: `{"asset_id": "asset-2026-001", "user": "analyst_1", "device_id": "usb-lex-01", "action": "copy_to_media", "reason": "policy_requires_media_approval", "requires_approval": true}`

- **lab/images/project-board.png** (`media_control`)
  - rule: media_action_warned
  - severity: medium
  - status: warned
  - evidence: `{"asset_id": "asset-2026-003", "user": "analyst_1", "device_id": "usb-lex-02", "action": "backup_to_media", "reason": "unsigned_write", "requires_approval": true}`

- **lab/secrets/.env** (`media_control`)
  - rule: media_action_blocked
  - severity: high
  - status: blocked
  - evidence: `{"asset_id": "asset-2026-004", "user": "analyst_3", "device_id": "usb-lex-01", "action": "copy_to_media", "reason": "secret_file_pattern", "requires_approval": true}`

## Limitations
- Synthetic demo content only.
- Evidence and policy data are anonymized.
- Not a replacement for enterprise DLP productization.
