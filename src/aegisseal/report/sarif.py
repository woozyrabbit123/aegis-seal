"""SARIF 2.1.0 report generator with deterministic output."""

import json
from pathlib import Path
from typing import Any, Dict, List

from aegisseal import __version__
from aegisseal.scanning.detectors import Finding, Rule
from aegisseal.utils.ids import compute_line_hash, get_rule_id, stable_sort_results


def generate_sarif_report(
    findings: List[Finding],
    rules: List[Rule],
    scan_root: Path,
) -> Dict[str, Any]:
    """
    Generate a SARIF 2.1.0 compliant report with deterministic output.

    Args:
        findings: List of findings
        rules: List of rules used in scan
        scan_root: Root directory of scan (for URI resolution)

    Returns:
        SARIF report as dictionary
    """
    # Create rule objects for SARIF with stable IDs
    sarif_rules = []
    rule_id_to_index = {}

    for rule in rules:
        rule_id = get_rule_id(rule.id)
        sarif_rule = {
            "id": rule_id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "defaultConfiguration": {"level": _severity_to_level(rule.severity)},
            "properties": {
                "tags": ["security", "secret"],
                "security-severity": _severity_to_score(rule.severity),
            },
        }
        sarif_rules.append(sarif_rule)

    # Sort rules deterministically by numeric ID, then by name
    sarif_rules.sort(key=lambda r: (_extract_numeric_id(r["id"]), r["name"]))

    # Build rule index map
    for idx, rule in enumerate(sarif_rules):
        rule_id_to_index[rule["id"]] = idx

    # Create results
    sarif_results = []
    for finding in findings:
        # Normalize path to posix
        file_uri = Path(finding.file_path).as_posix()

        # Get rule index
        rule_index = rule_id_to_index.get(finding.rule_id, 0)

        # Generate stable line hash for fingerprint
        line_hash = compute_line_hash(finding.line_content)

        result = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": _severity_to_level(finding.severity),
            "message": {"text": f"Potential secret detected: {finding.rule_name}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri},
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "fingerprints": {
                "primaryLocationLineHash": line_hash,
            },
            "properties": {
                "aegis:detector": "regex",
                "aegis:severity": finding.severity,
            },
        }
        sarif_results.append(result)

    # Sort results deterministically
    sarif_results = stable_sort_results(sarif_results)

    # Build SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
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
            }
        ],
    }

    return sarif


def save_sarif_report(
    sarif_data: Dict[str, Any],
    output_path: Path,
) -> None:
    """
    Save SARIF report to file with deterministic formatting.

    Args:
        sarif_data: SARIF report dictionary
        output_path: Path to save report
    """
    from aegisseal.utils.io import write_text_atomic

    # Use deterministic JSON encoding
    # - No sort_keys (we control order explicitly)
    # - Compact separators for smaller files
    # - ensure_ascii=False for UTF-8 support
    # - 2-space indent for readability
    json_str = json.dumps(
        sarif_data,
        indent=2,
        separators=(",", ": "),
        ensure_ascii=False,
        sort_keys=False,
    )

    # Write atomically
    write_text_atomic(output_path, json_str)


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


def _extract_numeric_id(rule_id: str) -> int:
    """
    Extract numeric part from rule ID (e.g., "AEGIS-1234" -> 1234).

    Args:
        rule_id: Rule ID string

    Returns:
        Numeric part as integer
    """
    try:
        return int(rule_id.split("-")[1])
    except (IndexError, ValueError):
        return 0
