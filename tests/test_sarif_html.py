"""Tests for SARIF and HTML report generation (Sprint A3)."""

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from aegisseal.report.html import generate_html_report
from aegisseal.report.sarif import generate_sarif_report
from aegisseal.scanning.detectors import Finding
from aegisseal.scanning.engine import ScanConfig, ScanEngine


@pytest.fixture
def temp_test_repo(tmp_path):
    """Create a minimal test repository with known secrets."""
    test_file = tmp_path / "test_secrets.py"
    test_file.write_text(
        '# Test file\n'
        'github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
        'aws_key = "AKIAIOSFODNN7EXAMPLE"\n'
    )
    return tmp_path


def test_sarif_minimal_schema(temp_test_repo):
    """Test that SARIF output contains all required fields per SARIF 2.1.0 schema."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    sarif_data = generate_sarif_report(result.findings, engine.rules, temp_test_repo)

    # Required top-level fields
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert "runs" in sarif_data
    assert len(sarif_data["runs"]) == 1

    run = sarif_data["runs"][0]

    # Required run fields
    assert "tool" in run
    assert "driver" in run["tool"]
    assert "results" in run

    driver = run["tool"]["driver"]

    # Required driver fields
    assert driver["name"] == "Aegis Seal"
    assert "semanticVersion" in driver  # SARIF uses semanticVersion, not version
    assert "informationUri" in driver
    assert "rules" in driver

    # Each rule must have required fields
    for rule in driver["rules"]:
        assert "id" in rule
        assert "name" in rule
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]
        assert "fullDescription" in rule
        assert "text" in rule["fullDescription"]
        assert "defaultConfiguration" in rule
        assert "level" in rule["defaultConfiguration"]
        assert "properties" in rule
        assert "tags" in rule["properties"]

    # Each result must have required fields
    for result_obj in run["results"]:
        assert "ruleId" in result_obj
        assert "ruleIndex" in result_obj
        assert "message" in result_obj
        assert "text" in result_obj["message"]
        assert "locations" in result_obj
        assert len(result_obj["locations"]) > 0

        location = result_obj["locations"][0]
        assert "physicalLocation" in location

        physical = location["physicalLocation"]
        assert "artifactLocation" in physical
        assert "uri" in physical["artifactLocation"]
        assert "region" in physical
        assert "startLine" in physical["region"]


def test_sarif_deterministic(temp_test_repo):
    """Test that SARIF output is byte-for-byte identical across multiple runs."""
    # Run scan twice
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)

    engine1 = ScanEngine(config)
    result1 = engine1.scan()
    sarif1 = generate_sarif_report(result1.findings, engine1.rules, temp_test_repo)

    engine2 = ScanEngine(config)
    result2 = engine2.scan()
    sarif2 = generate_sarif_report(result2.findings, engine2.rules, temp_test_repo)

    # Serialize to JSON with same settings
    json1 = json.dumps(sarif1, indent=2, separators=(",", ": "), ensure_ascii=False, sort_keys=False)
    json2 = json.dumps(sarif2, indent=2, separators=(",", ": "), ensure_ascii=False, sort_keys=False)

    # Compute hashes
    hash1 = hashlib.sha256(json1.encode("utf-8")).hexdigest()
    hash2 = hashlib.sha256(json2.encode("utf-8")).hexdigest()

    assert hash1 == hash2, "SARIF output must be deterministic across runs"
    assert json1 == json2, "SARIF JSON must be byte-identical"


def test_sarif_rule_index_alignment(temp_test_repo):
    """Test that ruleIndex in results corresponds to the correct rule in driver.rules."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    sarif_data = generate_sarif_report(result.findings, engine.rules, temp_test_repo)

    run = sarif_data["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    # Verify each result's ruleIndex points to the correct rule
    for result_obj in results:
        rule_id = result_obj["ruleId"]
        rule_index = result_obj["ruleIndex"]

        # Check that ruleIndex is valid
        assert 0 <= rule_index < len(rules), f"ruleIndex {rule_index} out of range"

        # Check that the rule at ruleIndex has the correct ID
        indexed_rule = rules[rule_index]
        assert indexed_rule["id"] == rule_id, \
            f"ruleIndex {rule_index} points to rule '{indexed_rule['id']}' but ruleId is '{rule_id}'"


def test_html_single_file(temp_test_repo):
    """Test that HTML report is a single file with no external dependencies."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    sarif_data = generate_sarif_report(result.findings, engine.rules, temp_test_repo)
    html_content = generate_html_report(result.findings, result.scanned_files, sarif_data)

    # Check for embedded SARIF data
    assert '<script id="sarif-data" type="application/json">' in html_content, \
        "HTML must contain embedded SARIF data"

    # Check that SARIF is actually embedded (not empty)
    start_idx = html_content.find('<script id="sarif-data" type="application/json">')
    end_idx = html_content.find('</script>', start_idx)
    sarif_block = html_content[start_idx:end_idx]
    assert len(sarif_block) > 100, "Embedded SARIF data should not be empty"

    # Verify no external dependencies
    assert 'href="http' not in html_content, "HTML must not reference external stylesheets"
    assert 'src="http' not in html_content, "HTML must not reference external scripts"
    assert '<link' not in html_content or '<link' not in html_content.split('<style>')[0], \
        "HTML must not use external <link> tags"

    # Check for inline styles
    assert '<style>' in html_content, "HTML must contain inline styles"

    # Check for inline script (besides SARIF data)
    assert html_content.count('<script>') >= 1, "HTML must contain inline JavaScript"


def test_html_counts_match_sarif(temp_test_repo):
    """Test that counts displayed in HTML match the SARIF result tallies."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    sarif_data = generate_sarif_report(result.findings, engine.rules, temp_test_repo)
    html_content = generate_html_report(result.findings, result.scanned_files, sarif_data)

    # Count findings by severity in SARIF
    sarif_results = sarif_data["runs"][0]["results"]
    sarif_severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for result_obj in sarif_results:
        severity = result_obj.get("properties", {}).get("aegis:severity", "medium").lower()
        if severity in sarif_severity_counts:
            sarif_severity_counts[severity] += 1

    # Extract counts from HTML (they're in the summary cards)
    import re

    # Total findings
    total_match = re.search(r'<h3>Total Findings</h3>\s*<div class="value">(\d+)</div>', html_content)
    assert total_match, "HTML must contain total findings count"
    html_total = int(total_match.group(1))
    assert html_total == len(sarif_results), "HTML total must match SARIF result count"

    # Severity counts
    for severity in ["critical", "high", "medium", "low"]:
        pattern = rf'<h3>{severity.capitalize()}</h3>\s*<div class="value[^"]*">(\d+)</div>'
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            html_count = int(match.group(1))
            assert html_count == sarif_severity_counts[severity], \
                f"HTML {severity} count ({html_count}) must match SARIF count ({sarif_severity_counts[severity]})"


def test_path_normalization(temp_test_repo):
    """Test that all file paths in SARIF are normalized to POSIX style."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    sarif_data = generate_sarif_report(result.findings, engine.rules, temp_test_repo)

    results = sarif_data["runs"][0]["results"]

    for result_obj in results:
        for location in result_obj["locations"]:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]

            # Check that paths use forward slashes (POSIX style)
            assert "\\" not in uri, f"URI must not contain backslashes: {uri}"

            # Check that path is relative and normalized
            assert not uri.startswith("/"), f"URI should be relative: {uri}"
            assert not uri.startswith("./"), f"URI should not start with ./: {uri}"
            assert "../" not in uri, f"URI should not contain parent references: {uri}"


def test_sarif_fingerprints_stable(temp_test_repo):
    """Test that SARIF fingerprints are stable and based on line content."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    sarif_data = generate_sarif_report(result.findings, engine.rules, temp_test_repo)
    results = sarif_data["runs"][0]["results"]

    for result_obj in results:
        # Check that fingerprints exist
        assert "fingerprints" in result_obj, "Each result must have fingerprints"
        fingerprints = result_obj["fingerprints"]

        # Check that primaryLocationLineHash exists
        assert "primaryLocationLineHash" in fingerprints, "Fingerprints must include primaryLocationLineHash"
        line_hash = fingerprints["primaryLocationLineHash"]

        # Verify it's a valid SHA-1 hash (40 hex chars)
        assert len(line_hash) == 40, "primaryLocationLineHash must be a SHA-1 hash (40 chars)"
        assert all(c in "0123456789abcdef" for c in line_hash), "primaryLocationLineHash must be hex"


def test_html_deterministic(temp_test_repo):
    """Test that HTML output is deterministic (no timestamps, random IDs)."""
    config = ScanConfig(target_path=temp_test_repo, enable_entropy=False)

    # Run twice
    engine1 = ScanEngine(config)
    result1 = engine1.scan()
    sarif1 = generate_sarif_report(result1.findings, engine1.rules, temp_test_repo)
    html1 = generate_html_report(result1.findings, result1.scanned_files, sarif1)

    engine2 = ScanEngine(config)
    result2 = engine2.scan()
    sarif2 = generate_sarif_report(result2.findings, engine2.rules, temp_test_repo)
    html2 = generate_html_report(result2.findings, result2.scanned_files, sarif2)

    # HTML should be identical
    hash1 = hashlib.sha256(html1.encode("utf-8")).hexdigest()
    hash2 = hashlib.sha256(html2.encode("utf-8")).hexdigest()

    assert hash1 == hash2, "HTML output must be deterministic"
    assert html1 == html2, "HTML must be byte-identical across runs"
