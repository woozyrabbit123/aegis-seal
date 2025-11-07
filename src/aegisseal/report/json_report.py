"""JSON report generator."""

import json
from pathlib import Path
from typing import Any, Dict, List

from aegisseal import __version__
from aegisseal.scanning.detectors import Finding


def generate_json_report(
    findings: List[Finding],
    scanned_files: int,
    suppressed_count: int = 0,
) -> Dict[str, Any]:
    """
    Generate a JSON report.

    Args:
        findings: List of findings
        scanned_files: Number of files scanned
        suppressed_count: Number of findings suppressed by baseline

    Returns:
        JSON report as dictionary
    """
    findings_data = []

    for finding in findings:
        finding_dict = {
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity,
            "file": finding.file_path,
            "line": finding.line_number,
            "redacted_match": finding.redacted_match,
            "line_content": finding.line_content.strip(),
        }
        findings_data.append(finding_dict)

    # Group findings by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "version": __version__,
        "summary": {
            "total_findings": len(findings),
            "scanned_files": scanned_files,
            "suppressed_findings": suppressed_count,
            "by_severity": severity_counts,
        },
        "findings": findings_data,
    }

    return report


def save_json_report(
    json_data: Dict[str, Any],
    output_path: Path,
) -> None:
    """
    Save JSON report to file.

    Args:
        json_data: JSON report dictionary
        output_path: Path to save report
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, sort_keys=True)
