"""Generate a synthetic but structured data protection case study report."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


BUILT_IN_POLICIES = {
    "portfolio-lab": {
        "policy_id": "dp-cs-2026-001",
        "environment": "portfolio-lab",
        "owner": "security-portfolio",
        "metadata_checks": {
            "require_stripped_exif": True,
            "disallow_sensitive_keys": [
                "CameraModel",
                "GPSLatitude",
                "GPSLongitude",
                "GeoAltitude",
                "Author",
            ],
            "required_fields_after_sanitize": [
                "filesize",
                "mime_type",
                "sha256",
                "sanitized",
            ],
        },
        "secret_checks": {
            "forbidden_patterns": [
                "API_KEY",
                "AWS_SECRET",
                "PRIVATE_KEY",
                "SSH_KEY",
                "INTERNAL_TOKEN",
                "DB_PASSWORD",
            ],
            "severity_threshold": "medium",
        },
        "media_rules": {
            "disallow_auto_copy": True,
            "disallow_unsigned_export": True,
            "require_media_approval": True,
        },
        "notes": [
            "Synthetic-only dataset.",
            "No client data is represented in this repository.",
        ],
    },
    "enterprise-lab": {
        "policy_id": "dp-cs-2026-ENTERPRISE",
        "environment": "enterprise-lab",
        "owner": "security-portfolio",
        "metadata_checks": {
            "require_stripped_exif": True,
            "disallow_sensitive_keys": [
                "CameraModel",
                "GPSLatitude",
                "GPSLongitude",
                "GeoAltitude",
                "Author",
                "Software",
            ],
            "required_fields_after_sanitize": [
                "filesize",
                "mime_type",
                "sha256",
                "sanitized",
            ],
        },
        "secret_checks": {
            "forbidden_patterns": [
                "API_KEY",
                "AWS_SECRET",
                "PRIVATE_KEY",
                "SSH_KEY",
                "INTERNAL_TOKEN",
                "DB_PASSWORD",
                "PERSONAL_TOKEN",
            ],
            "severity_threshold": "high",
        },
        "media_rules": {
            "disallow_auto_copy": True,
            "disallow_unsigned_export": True,
            "require_media_approval": True,
        },
        "notes": [
            "Synthetic and sanitized datasets only.",
            "Explicitly scoped for portfolio-safe demonstration.",
        ],
    },
}


EVIDENCE_TO_CONTROL = {
    ("metadata", "metadata_removed"): {
        "id": "DP-METADATA-01",
        "name": "Metadata sanitization",
        "objective": "Remove sensitive metadata from outbound/distributed artifacts.",
    },
    ("metadata", "metadata_check_required"): {
        "id": "DP-METADATA-02",
        "name": "Metadata verification",
        "objective": "Flag residual sensitive metadata fields for remediation.",
    },
    ("secret_discovery", "forbidden_pattern_found"): {
        "id": "DP-SECRET-01",
        "name": "Secret leak control",
        "objective": "Detect forbidden secret patterns in sample evidence.",
    },
    ("secret_discovery", "non_forbidden_pattern"): {
        "id": "DP-SECRET-02",
        "name": "Token hygiene review",
        "objective": "Track potentially sensitive patterns that may still warrant review.",
    },
    ("media_control", "media_action_blocked"): {
        "id": "DP-MEDIA-01",
        "name": "Removable media governance",
        "objective": "Block or reject high-risk media transfer actions.",
    },
    ("media_control", "media_action_warned"): {
        "id": "DP-MEDIA-02",
        "name": "Media transfer warning controls",
        "objective": "Expose medium-risk transfer events before approval.",
    },
    ("media_control", "approved_media_transfer"): {
        "id": "DP-MEDIA-03",
        "name": "Media transfer approval workflow",
        "objective": "Track approved transfer cases with auditable context.",
    },
    ("default", "default"): {
        "id": "DP-GEN-01",
        "name": "General evidence control",
        "objective": "Maintain traceability between observed evidence and control intent.",
    },
}


def evidence_to_control(category: str, rule: str) -> Dict[str, str]:
    return EVIDENCE_TO_CONTROL.get(
        (category, rule),
        EVIDENCE_TO_CONTROL[("default", "default")],
    )


def build_controls_matrix(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    controls: Dict[str, Dict[str, str]] = {}
    for item in findings:
        control = item.get("control", {})
        control_id = control.get("id", "DP-GEN-01")
        controls[control_id] = control
    return sorted(controls.values(), key=lambda c: c.get("id", ""))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Data protection case study")
    parser.add_argument("--metadata", required=True, help="Path to metadata inventory JSONL")
    parser.add_argument("--secrets", required=True, help="Path to secret scan JSONL")
    parser.add_argument("--media", required=True, help="Path to media event JSONL")
    parser.add_argument(
        "--policy",
        help="Path to policy JSON (optional; falls back to built-in policy profile)",
    )
    parser.add_argument(
        "--policy-name",
        choices=sorted(BUILT_IN_POLICIES.keys()),
        default="portfolio-lab",
        help="Built-in policy profile name",
    )
    parser.add_argument("--output", required=True, help="Directory to write outputs")
    parser.add_argument(
        "--baseline",
        required=False,
        default=None,
        help="Optional baseline report JSON path for diff-style output.",
    )
    parser.add_argument(
        "--baseline-output",
        dest="baseline_output",
        required=False,
        default=None,
        help="Alias for --baseline. Keeps compatibility with planned command names.",
    )
    return parser.parse_args()


def load_json(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def severity_for_secret(confidence: str, rule: str) -> str:
    if confidence.lower() == "high" or rule in {"API_KEY", "AWS_SECRET", "PRIVATE_KEY", "DB_PASSWORD"}:
        return "high"
    if confidence.lower() == "medium":
        return "medium"
    return "low"


def evaluate_metadata(policy: Dict[str, Any], metadata_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    checks = policy.get("metadata_checks", {})
    forbidden = set(checks.get("disallow_sensitive_keys", []))

    for row in metadata_rows:
        before_exif = row.get("before", {}).get("exif", {}) or {}
        after_exif = row.get("after", {}).get("exif", {}) or {}

        for field in forbidden:
            if before_exif.get(field) is not None and after_exif.get(field) is None:
                findings.append(
                    {
                        "category": "metadata",
                        "asset": row.get("path"),
                        "rule": "metadata_removed",
                        "severity": "low",
                        "status": "remediated",
                        "control": evidence_to_control("metadata", "metadata_removed"),
                        "evidence": {
                            "field": field,
                            "before": before_exif.get(field),
                            "after": after_exif.get(field),
                        },
                    }
                )
            elif before_exif.get(field) is not None:
                findings.append(
                    {
                        "category": "metadata",
                        "asset": row.get("path"),
                        "rule": "metadata_check_required",
                        "severity": "medium",
                        "status": "residual_risk",
                        "control": evidence_to_control("metadata", "metadata_check_required"),
                        "evidence": {
                            "field": field,
                            "value": before_exif.get(field),
                        },
                    }
                )

    return findings


def evaluate_secrets(policy: Dict[str, Any], secret_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    forbidden = set(policy.get("secret_checks", {}).get("forbidden_patterns", []))

    for row in secret_rows:
        rule = row.get("matched_rule", "")
        severity = severity_for_secret(row.get("confidence", "low"), rule)
        if rule in forbidden:
            findings.append(
                {
                    "category": "secret_discovery",
                    "asset": row.get("file"),
                    "rule": "forbidden_pattern_found",
                    "severity": severity,
                    "status": "high_risk",
                    "control": evidence_to_control("secret_discovery", "forbidden_pattern_found"),
                    "evidence": {
                        "line": row.get("line"),
                        "type": row.get("type"),
                        "matched_rule": rule,
                        "confidence": row.get("confidence"),
                    },
                }
            )
        else:
            findings.append(
                {
                    "category": "secret_discovery",
                    "asset": row.get("file"),
                    "rule": "non_forbidden_pattern",
                    "severity": "low",
                    "status": "informational",
                    "control": evidence_to_control("secret_discovery", "non_forbidden_pattern"),
                    "evidence": {
                        "line": row.get("line"),
                        "type": row.get("type"),
                        "matched_rule": rule,
                    },
                }
            )

    return findings


def evaluate_media(policy: Dict[str, Any], media_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    rules = policy.get("media_rules", {})
    for row in media_rows:
        reason = row.get("reason", "")
        result = row.get("result", "")
        if result in {"blocked", "warned"}:
            findings.append(
                {
                    "category": "media_control",
                    "asset": row.get("file"),
                    "rule": f"media_action_{result}",
                    "severity": "medium" if result == "warned" else "high",
                    "status": result,
                    "control": evidence_to_control("media_control", f"media_action_{result}"),
                    "evidence": {
                        "asset_id": row.get("asset_id"),
                        "user": row.get("user"),
                        "device_id": row.get("device_id"),
                        "action": row.get("action"),
                        "reason": reason,
                        "requires_approval": rules.get("require_media_approval", True),
                    },
                }
            )
        elif result == "allowed" and reason == "signed_copy":
            findings.append(
                {
                    "category": "media_control",
                    "asset": row.get("file"),
                    "rule": "approved_media_transfer",
                    "severity": "low",
                    "status": "compliant",
                    "control": evidence_to_control("media_control", "approved_media_transfer"),
                    "evidence": {"asset_id": row.get("asset_id"), "user": row.get("user")},
                }
            )
    return findings


def _escape_markdown_cell(value: str) -> str:
    return str(value).replace("|", "\\|")


def _finding_identity(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    evidence_id = ""
    if isinstance(evidence, dict):
        for field in ("field", "line", "asset_id", "file", "path", "type"):
            if evidence.get(field) is not None:
                evidence_id = str(evidence.get(field))
                break

    return "|".join(
        [
            str(finding.get("asset", "")),
            str(finding.get("category", "")),
            str(finding.get("rule", "")),
            evidence_id,
        ]
    )


def _compare_with_baseline(
    current_findings: List[Dict[str, Any]],
    baseline_findings: List[Dict[str, Any]] | None,
) -> Dict[str, Any]:
    if not baseline_findings:
        return {
            "enabled": False,
            "summary": {
                "status": "not_run",
                "current_findings": len(current_findings),
                "baseline_findings": 0,
                "added": 0,
                "resolved": 0,
                "changed": 0,
                "unchanged": len(current_findings),
            },
            "added": [],
            "resolved": [],
            "changed": [],
            "unchanged_count": len(current_findings),
        }

    from collections import defaultdict

    baseline_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in baseline_findings:
        baseline_map[_finding_identity(item)].append(item)

    added: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []

    for item in current_findings:
        key = _finding_identity(item)
        candidate = None
        if key in baseline_map and baseline_map[key]:
            candidate = baseline_map[key].pop(0)

        if candidate is None:
            added.append(
                {
                    "asset": item.get("asset"),
                    "category": item.get("category"),
                    "rule": item.get("rule"),
                    "status": item.get("status"),
                    "severity": item.get("severity"),
                }
            )
            continue

        differences = []
        if item.get("status") != candidate.get("status"):
            differences.append("status")
        if item.get("severity") != candidate.get("severity"):
            differences.append("severity")

        if item.get("control", {}).get("id") != candidate.get("control", {}).get("id"):
            differences.append("control")

        if not differences:
            unchanged.append(
                {
                    "asset": item.get("asset"),
                    "category": item.get("category"),
                    "rule": item.get("rule"),
                    "status": item.get("status"),
                    "severity": item.get("severity"),
                }
            )
            continue

        changed.append(
            {
                "asset": item.get("asset"),
                "category": item.get("category"),
                "rule": item.get("rule"),
                "differences": differences,
                "current": {
                    "status": item.get("status"),
                    "severity": item.get("severity"),
                },
                "baseline": {
                    "status": candidate.get("status"),
                    "severity": candidate.get("severity"),
                },
            }
        )

    resolved: List[Dict[str, Any]] = []
    for key in list(baseline_map.keys()):
        for item in baseline_map[key]:
            resolved.append(
                {
                    "asset": item.get("asset"),
                    "category": item.get("category"),
                    "rule": item.get("rule"),
                    "status": item.get("status"),
                    "severity": item.get("severity"),
                }
            )

    return {
        "enabled": True,
        "summary": {
            "status": "completed",
            "current_findings": len(current_findings),
            "baseline_findings": len(baseline_findings),
            "added": len(added),
            "resolved": len(resolved),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "added": added[:10],
        "resolved": resolved[:10],
        "changed": changed[:10],
        "unchanged_count": len(unchanged),
    }


def build_report(
    policy: Dict[str, Any],
    findings: List[Dict[str, Any]],
    baseline_findings: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "case_id": policy.get("policy_id", "dp-cs-manual"),
        "scope": {
            "environment": policy.get("environment", "lab"),
            "policy_owner": policy.get("owner", "unknown"),
            "notes": policy.get("notes", []),
        },
        "stats": {
            "total_findings": len(findings),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
        },
        "controls": build_controls_matrix(findings),
        "findings": findings,
        "baseline_comparison": _compare_with_baseline(findings, baseline_findings),
    }


def write_json(output_dir: Path, payload: Dict[str, Any]) -> None:
    output_dir.joinpath("data_protection_report.json").write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )


def write_markdown(output_dir: Path, payload: Dict[str, Any]) -> None:
    comparison = payload.get("baseline_comparison", {})
    lines = [
        "# Data Protection Case Study Report",
        "",
        f"**Case ID:** {payload['case_id']}",
        f"**Generated at:** {payload['generated_at']}",
        "",
        "## Summary",
        f"- Total findings: {payload['stats']['total_findings']}",
        f"- High: {payload['stats']['high']}",
        f"- Medium: {payload['stats']['medium']}",
        f"- Low: {payload['stats']['low']}",
        "",
        "## Scope",
        f"- Environment: `{payload['scope']['environment']}`",
        f"- Owner: `{payload['scope']['policy_owner']}`",
        "",
        "## Findings",
        "",
    ]

    for finding in payload["findings"]:
        control = finding["control"]
        lines.extend(
            [
                f"- **{finding['asset']}** (`{finding['category']}`)",
                f"  - rule: {finding['rule']}",
                f"  - severity: {finding['severity']}",
                f"  - status: {finding['status']}",
                f"  - control: {control['id']} ({control['name']})",
                f"  - objective: {control['objective']}",
                f"  - evidence: `{json.dumps(finding['evidence'], ensure_ascii=False)}`",
                "",
            ]
        )

    lines.extend(
        [
            "## Evidence-to-control mapping",
            "",
            "| Evidence | Rule | Control ID | Control | Objective |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in payload["findings"]:
        control = finding["control"]
        lines.append(
            "| "
            + _escape_markdown_cell(finding["asset"])
            + " | "
            + _escape_markdown_cell(finding["rule"])
            + " | "
            + _escape_markdown_cell(control["id"])
            + " | "
            + _escape_markdown_cell(control["name"])
            + " | "
            + _escape_markdown_cell(control["objective"])
            + " |"
        )

    lines.extend(
        [
            "## Limitations",
            "- Synthetic demo content only.",
            "- Evidence and policy data are anonymized.",
            "- Not a replacement for enterprise DLP productization.",
            "",
        ]
    )

    if comparison.get("enabled"):
        summary = comparison.get("summary", {})
        lines.extend(
            [
                "## What changed",
                f"- Baseline findings: {summary.get('baseline_findings', 0)}",
                f"- Current findings: {summary.get('current_findings', 0)}",
                f"- Added: {summary.get('added', 0)}",
                f"- Resolved: {summary.get('resolved', 0)}",
                f"- Changed: {summary.get('changed', 0)}",
                f"- Unchanged: {summary.get('unchanged', 0)}",
                "",
            ]
        )

        if comparison.get("added"):
            lines.extend(["### Added findings"])
            for item in comparison["added"]:
                lines.append(
                    f"- **{item['asset']}** ({item['category']}) — `{item['rule']}` ({item['status']}, {item['severity']})"
                )
            lines.append("")

        if comparison.get("resolved"):
            lines.extend(["### Resolved findings"])
            for item in comparison["resolved"]:
                lines.append(
                    f"- **{item['asset']}** ({item['category']}) — `{item['rule']}` ({item['status']}, {item['severity']})"
                )
            lines.append("")

        if comparison.get("changed"):
            lines.extend(["### Changed findings"])
            for item in comparison["changed"]:
                lines.append(
                    f"- **{item['asset']}** ({item['category']}) — `{item['rule']}` "
                    f"(diff: {', '.join(item['differences'])})"
                )
            lines.append("")

    output_dir.joinpath("data_protection_report.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def write_csv(output_dir: Path, findings: List[Dict[str, Any]]) -> None:
    output_file = output_dir.joinpath("data_protection_findings.csv")
    with output_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "asset",
                "category",
                "rule",
                "severity",
                "status",
                "control_id",
                "control_name",
                "control_objective",
                "evidence",
            ]
        )
        for item in findings:
            control = item["control"]
            writer.writerow(
                [
                    item["asset"],
                    item["category"],
                    item["rule"],
                    item["severity"],
                    item["status"],
                    control["id"],
                    control["name"],
                    control["objective"],
                    json.dumps(item["evidence"], ensure_ascii=False),
                ]
            )


def main() -> None:
    args = parse_args()
    metadata_rows = load_jsonl(args.metadata)
    secret_rows = load_jsonl(args.secrets)
    media_rows = load_jsonl(args.media)
    if args.policy:
        policy = load_json(args.policy)
    else:
        policy = BUILT_IN_POLICIES[args.policy_name]

    findings: List[Dict[str, Any]] = []
    findings.extend(evaluate_metadata(policy, metadata_rows))
    findings.extend(evaluate_secrets(policy, secret_rows))
    findings.extend(evaluate_media(policy, media_rows))

    baseline_report_path = args.baseline_output or args.baseline
    baseline_findings: List[Dict[str, Any]] | None = None
    if baseline_report_path:
        baseline_payload = load_json(baseline_report_path)
        if isinstance(baseline_payload, dict):
            baseline_findings = baseline_payload.get("findings")

    payload = build_report(policy, findings, baseline_findings=baseline_findings)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir, payload)
    write_markdown(output_dir, payload)
    write_csv(output_dir, findings)

    print(f"Data protection case study outputs written to {output_dir}")


if __name__ == "__main__":
    main()
