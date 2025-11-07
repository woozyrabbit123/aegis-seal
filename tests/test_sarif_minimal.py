"""Tests for SARIF 2.1.0 report generation."""

import json
import tempfile
from pathlib import Path

import pytest

from aegisseal.report.sarif import generate_sarif_report
from aegisseal.scanning.detectors import Finding, load_default_rules


def test_sarif_minimal_structure():
    """Test that SARIF report has minimal valid structure."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="GitHub PAT",
            file_path="test.py",
            line_number=10,
            line_content="token = 'ghp_1234567890123456789012345678901234AB'",
            matched_string="ghp_1234567890123456789012345678901234AB",
            severity="high",
            redacted_match="ghp_1234...",
        )
    ]

    rules = load_default_rules()
    sarif = generate_sarif_report(findings, rules, Path("/tmp"))

    # Check required fields
    assert sarif["$schema"]
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) > 0

    run = sarif["runs"][0]
    assert "tool" in run
    assert "driver" in run["tool"]
    assert run["tool"]["driver"]["name"] == "Aegis Seal"
    assert "semanticVersion" in run["tool"]["driver"]


def test_sarif_rules_section():
    """Test that SARIF includes rules section."""
    findings = []
    rules = load_default_rules()
    sarif = generate_sarif_report(findings, rules, Path("/tmp"))

    run = sarif["runs"][0]
    assert "rules" in run["tool"]["driver"]
    sarif_rules = run["tool"]["driver"]["rules"]

    assert len(sarif_rules) > 0

    # Check rule structure
    for rule in sarif_rules:
        assert "id" in rule
        assert rule["id"].startswith("AEGIS-")
        assert "name" in rule
        assert "shortDescription" in rule
        assert "fullDescription" in rule


def test_sarif_results_section():
    """Test that SARIF includes results correctly."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="GitHub PAT",
            file_path="test.py",
            line_number=10,
            line_content="token = 'ghp_1234567890123456789012345678901234AB'",
            matched_string="ghp_1234567890123456789012345678901234AB",
            severity="high",
            redacted_match="ghp_1234...",
        )
    ]

    rules = load_default_rules()
    sarif = generate_sarif_report(findings, rules, Path("/tmp"))

    run = sarif["runs"][0]
    assert "results" in run
    assert len(run["results"]) == 1

    result = run["results"][0]
    assert result["ruleId"] == "AEGIS-1001"
    assert result["level"] in ["error", "warning", "note"]
    assert "message" in result
    assert "locations" in result

    location = result["locations"][0]
    assert "physicalLocation" in location
    assert "artifactLocation" in location["physicalLocation"]
    assert "region" in location["physicalLocation"]


def test_sarif_fingerprints():
    """Test that SARIF includes fingerprints for deduplication."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="GitHub PAT",
            file_path="test.py",
            line_number=10,
            line_content="token = 'ghp_1234567890123456789012345678901234AB'",
            matched_string="ghp_1234567890123456789012345678901234AB",
            severity="high",
            redacted_match="ghp_1234...",
        )
    ]

    rules = load_default_rules()
    sarif = generate_sarif_report(findings, rules, Path("/tmp"))

    result = sarif["runs"][0]["results"][0]
    assert "partialFingerprints" in result
    assert "primaryLocationLineHash" in result["partialFingerprints"]


def test_sarif_deterministic_output():
    """Test that SARIF output is deterministic."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="GitHub PAT",
            file_path="test.py",
            line_number=10,
            line_content="token = 'ghp_1234567890123456789012345678901234AB'",
            matched_string="ghp_1234567890123456789012345678901234AB",
            severity="high",
            redacted_match="ghp_1234...",
        )
    ]

    rules = load_default_rules()

    # Generate twice
    sarif1 = generate_sarif_report(findings, rules, Path("/tmp"))
    sarif2 = generate_sarif_report(findings, rules, Path("/tmp"))

    # Convert to JSON and compare
    json1 = json.dumps(sarif1, sort_keys=True)
    json2 = json.dumps(sarif2, sort_keys=True)

    assert json1 == json2


def test_sarif_saves_to_file():
    """Test that SARIF can be saved to file."""
    from aegisseal.report.sarif import save_sarif_report

    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="GitHub PAT",
            file_path="test.py",
            line_number=10,
            line_content="token = 'ghp_1234567890123456789012345678901234AB'",
            matched_string="ghp_1234567890123456789012345678901234AB",
            severity="high",
            redacted_match="ghp_1234...",
        )
    ]

    rules = load_default_rules()
    sarif = generate_sarif_report(findings, rules, Path("/tmp"))

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        output_path = tmpdir / "test.sarif"

        save_sarif_report(sarif, output_path)

        assert output_path.exists()

        # Validate JSON
        with open(output_path) as f:
            loaded_sarif = json.load(f)

        assert loaded_sarif["version"] == "2.1.0"
