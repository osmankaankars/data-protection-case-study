# Quick publish steps (this machine)

This repository is currently ready as files, but not yet a git repository. Run:

```bash
cd /Users/kaan/Projects/data-protection-case-study
git init
git add .
git commit -m "chore: initialize data protection case study"

git remote add origin https://github.com/osmankaankars/data-protection-case-study.git
git branch -M main
git push -u origin main

# Create release tag
git tag -a v0.1.0 -m "case study release v0.1.0"
git push origin v0.1.0
```

If you use GitHub CLI (`gh`) and want release notes in one command:

```bash
gh release create v0.1.0 \
  --repo osmankaankars/data-protection-case-study \
  --title "Data Protection Case Study v0.1.0" \
  --notes-file release-notes-v0.1.0.md \
  output/data_protection_report.json \
  output/data_protection_report.md \
  output/data_protection_findings.csv
```

Release body is already prepared in [release-notes-v0.1.0.md](release-notes-v0.1.0.md).

