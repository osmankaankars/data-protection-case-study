# GitHub publishing pack

## Suggested repository metadata

- Name: `data-protection-case-study`
- Description: `Portfolio case study: evidence-linked data protection workflow with synthetic artifacts`
- Topics: `cybersecurity`, `privacy`, `case-study`, `data-protection`, `python`, `reproducible`
- Visibility: `public`
- License: `MIT`

## Release checklist

- Version: `v0.1.0`
- Assets to be generated before release:
  - `output/data_protection_report.json`
  - `output/data_protection_report.md`
  - `output/data_protection_findings.csv`
- Tag message: `feat(case-study): add data protection workflow v0.1.0`

## Files to include

- `README.md`
- `scripts/data_protection_case_study.py`
- `data/raw/*`
- `templates/data_protection_report_template.md`
- `output/*` (selected generated artifacts only)
- `LICENSE`
- `PUBLISHING.md`

## One-time publish flow

1. Generate outputs with the command in README.
2. Copy generated outputs from `output/` if you want clean release contents.
3. Create a public repository with the metadata above.
4. Upload all files and create release `v0.1.0`.
5. Add the repository URL to the profile roadmap section.

