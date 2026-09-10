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
                    "evidence": {"asset_id": row.get("asset_id"), "user": row.get("user")},
                }
            )
    return findings


def build_report(policy: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        "findings": findings,
    }


def write_json(output_dir: Path, payload: Dict[str, Any]) -> None:
    output_dir.joinpath("data_protection_report.json").write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )


def write_markdown(output_dir: Path, payload: Dict[str, Any]) -> None:
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
        lines.extend(
            [
                f"- **{finding['asset']}** (`{finding['category']}`)",
                f"  - rule: {finding['rule']}",
                f"  - severity: {finding['severity']}",
                f"  - status: {finding['status']}",
                f"  - evidence: `{json.dumps(finding['evidence'], ensure_ascii=False)}`",
                "",
            ]
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
    output_dir.joinpath("data_protection_report.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def write_csv(output_dir: Path, findings: List[Dict[str, Any]]) -> None:
    output_file = output_dir.joinpath("data_protection_findings.csv")
    with output_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["asset", "category", "rule", "severity", "status", "evidence"])
        for item in findings:
            writer.writerow(
                [
                    item["asset"],
                    item["category"],
                    item["rule"],
                    item["severity"],
                    item["status"],
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

    payload = build_report(policy, findings)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir, payload)
    write_markdown(output_dir, payload)
    write_csv(output_dir, findings)

    print(f"Data protection case study outputs written to {output_dir}")


if __name__ == "__main__":
    main()
