"""SARIF 2.1.0 report generator."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from aegisseal import __version__
from aegisseal.scanning.detectors import Finding, Rule


def generate_sarif_report(
    findings: List[Finding],
    rules: List[Rule],
    scan_root: Path,
) -> Dict[str, Any]:
    """
    Generate a SARIF 2.1.0 compliant report.

    Args:
        findings: List of findings
        rules: List of rules used in scan
        scan_root: Root directory of scan (for URI resolution)

    Returns:
        SARIF report as dictionary
    """
    # Create rule objects for SARIF
    sarif_rules = []
    rule_map = {}

    for rule in rules:
        from aegisseal.utils.ids import get_rule_id

        rule_id = get_rule_id(rule.id)
        rule_map[rule_id] = rule

        sarif_rule = {
            "id": rule_id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "help": {
                "text": f"{rule.description}\nSeverity: {rule.severity.upper()}",
                "markdown": f"**{rule.name}**\n\n{rule.description}\n\n**Severity:** {rule.severity.upper()}",
            },
            "properties": {
                "tags": ["security", "secret"],
                "security-severity": _severity_to_score(rule.severity),
            },
            "defaultConfiguration": {"level": _severity_to_level(rule.severity)},
        }
        sarif_rules.append(sarif_rule)

    # Create results
    sarif_results = []
    for finding in findings:
        # Generate fingerprint for deduplication
        fingerprint = _generate_fingerprint(finding)

        result = {
            "ruleId": finding.rule_id,
            "level": _severity_to_level(finding.severity),
            "message": {
                "text": f"Potential secret detected: {finding.rule_name}",
                "markdown": f"**Potential secret detected:** {finding.rule_name}\n\nRedacted match: `{finding.redacted_match}`",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": 1,
                            "snippet": {
                                "text": _redact_line_content(finding.line_content)
                            },
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint,
            },
        }
        sarif_results.append(result)

    # Build SARIF document
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis Seal",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/aegis-seal/aegis-seal",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": f"file://{scan_root.resolve()}/"}
                },
            }
        ],
    }

    return sarif


def save_sarif_report(
    sarif_data: Dict[str, Any],
    output_path: Path,
) -> None:
    """
    Save SARIF report to file.

    Args:
        sarif_data: SARIF report dictionary
        output_path: Path to save report
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2, sort_keys=True)


def _severity_to_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return severity_map.get(severity.lower(), "warning")


def _severity_to_score(severity: str) -> str:
    """Convert severity to security severity score (0.0-10.0)."""
    severity_map = {
        "critical": "9.0",
        "high": "7.0",
        "medium": "5.0",
        "low": "3.0",
    }
    return severity_map.get(severity.lower(), "5.0")


def _generate_fingerprint(finding: Finding) -> str:
    """
    Generate a stable fingerprint for a finding.

    Args:
        finding: The finding

    Returns:
        SHA256 hash (first 16 chars)
    """
    # Use file path, line number, and rule ID for fingerprint
    fingerprint_input = f"{finding.file_path}:{finding.line_number}:{finding.rule_id}"
    hash_obj = hashlib.sha256(fingerprint_input.encode("utf-8"))
    return hash_obj.hexdigest()[:16]


def _redact_line_content(line: str, max_length: int = 200) -> str:
    """
    Redact and truncate line content for display.

    Args:
        line: Line content
        max_length: Maximum length

    Returns:
        Redacted and truncated line
    """
    # Truncate if too long
    if len(line) > max_length:
        line = line[:max_length] + "..."

    # Strip leading/trailing whitespace
    return line.strip()
