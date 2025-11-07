"""Tests for HTML report generation."""

import tempfile
from pathlib import Path

import pytest

from aegisseal.report.html import generate_html_report, save_html_report
from aegisseal.report.sarif import generate_sarif_report
from aegisseal.scanning.detectors import Finding
from aegisseal.scanning.detectors import load_default_rules


def _generate_sarif_for_findings(findings):
    """Helper to generate SARIF data for findings."""
    rules = load_default_rules()
    return generate_sarif_report(findings, rules, Path("."))


def test_html_generation():
    """Test that HTML report is generated."""
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

    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=1, sarif_data=sarif_data)

    assert isinstance(html, str)
    assert len(html) > 0


def test_html_contains_required_elements():
    """Test that HTML contains required elements."""
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

    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=1, sarif_data=sarif_data)

    # Check for essential HTML elements
    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "<head>" in html
    assert "<body>" in html
    assert "Aegis Seal" in html


def test_html_inline_styles():
    """Test that HTML includes inline styles (single-file)."""
    findings = []
    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=0, sarif_data=sarif_data)

    # Should have inline CSS
    assert "<style>" in html
    assert "</style>" in html

    # Should not reference external stylesheets
    assert 'rel="stylesheet"' not in html


def test_html_inline_javascript():
    """Test that HTML includes inline JavaScript."""
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

    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=1, sarif_data=sarif_data)

    # Should have inline JavaScript (now with embedded SARIF)
    assert "<script>" in html
    assert "</script>" in html
    assert 'id="sarif-data"' in html  # Updated: now uses embedded SARIF

    # Should not reference external scripts
    assert '<script src="http' not in html  # Updated to check for http specifically


def test_html_dark_mode():
    """Test that HTML includes dark mode styles."""
    findings = []
    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=0, sarif_data=sarif_data)

    # Check for dark mode color variables
    assert "--bg-primary" in html or "background-color:" in html
    assert "#1a1a1a" in html or "dark" in html.lower()


def test_html_severity_counts():
    """Test that HTML includes severity counts."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="Test",
            file_path="test.py",
            line_number=1,
            line_content="line",
            matched_string="match",
            severity="critical",
            redacted_match="...",
        ),
        Finding(
            rule_id="AEGIS-1002",
            rule_name="Test2",
            file_path="test.py",
            line_number=2,
            line_content="line",
            matched_string="match",
            severity="high",
            redacted_match="...",
        ),
    ]

    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=1, sarif_data=sarif_data)

    # Should show counts
    assert "Critical" in html or "critical" in html
    assert "High" in html or "high" in html


def test_html_client_side_filtering():
    """Test that HTML includes client-side filtering."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="Test",
            file_path="test.py",
            line_number=1,
            line_content="line",
            matched_string="match",
            severity="high",
            redacted_match="...",
        )
    ]

    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=1, sarif_data=sarif_data)

    # Should have filter controls
    assert "filter" in html.lower()
    assert "checkbox" in html.lower()


def test_html_saves_to_file():
    """Test that HTML can be saved to file."""
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="Test",
            file_path="test.py",
            line_number=1,
            line_content="line",
            matched_string="match",
            severity="high",
            redacted_match="...",
        )
    ]

    sarif_data = _generate_sarif_for_findings(findings)
    html = generate_html_report(findings, scanned_files=1, sarif_data=sarif_data)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        output_path = tmpdir / "report.html"

        save_html_report(html, output_path)

        assert output_path.exists()

        # Read and verify
        with open(output_path) as f:
            loaded_html = f.read()

        assert "Aegis Seal" in loaded_html
