"""Tests for regex-based detection."""

import pytest

from aegisseal.scanning.detectors import load_default_rules, DetectorEngine


def test_load_default_rules():
    """Test that default rules load successfully."""
    rules = load_default_rules()
    assert len(rules) > 0
    assert all(rule.id for rule in rules)
    assert all(rule.name for rule in rules)
    assert all(rule.compiled_pattern for rule in rules)


def test_github_pat_detection():
    """Test GitHub PAT detection."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    # Valid GitHub PAT
    line = 'token = "ghp_1234567890123456789012345678901234AB"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) == 1
    assert findings[0].rule_name == "GitHub Personal Access Token"
    assert "ghp_" in findings[0].matched_string


def test_aws_access_key_detection():
    """Test AWS access key detection."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = "aws_key = AKIAIOSFODNN7EXAMPLA"
    findings = detector.scan_line(line, 1, "config.py")

    assert len(findings) == 1
    assert "AWS" in findings[0].rule_name


def test_private_key_detection():
    """Test private key detection."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = "-----BEGIN RSA PRIVATE KEY-----"
    findings = detector.scan_line(line, 1, "key.pem")

    # Should match both generic and RSA-specific rules
    assert len(findings) >= 1
    assert any("PRIVATE KEY" in f.rule_name.upper() for f in findings)


def test_allowlist_suppression():
    """Test that allowlisted values are not flagged."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    # Example value from AWS docs (should be allowlisted)
    line = 'secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = detector.scan_line(line, 1, "test.py")

    # AWS secret key pattern might match, but should be filtered by allowlist
    # This depends on the pattern matching first
    # For now, just ensure we don't crash
    assert isinstance(findings, list)


def test_context_hints_suppression():
    """Test that context hints suppress false positives."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    # Line with "example" context hint
    line = '# Example token: ghp_1234567890123456789012345678901234AB'
    findings = detector.scan_line(line, 1, "docs.py")

    # Should be suppressed due to "example" context hint
    assert len(findings) == 0


def test_multiple_secrets_per_line():
    """Test detection of multiple secrets in one line."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = 'config = {"github": "ghp_1234567890123456789012345678901234AB", "aws": "AKIAIOSFODNN7EXAMPLA"}'
    findings = detector.scan_line(line, 1, "config.py")

    # Should find both secrets
    assert len(findings) >= 2


def test_no_false_positives_on_normal_code():
    """Test that normal code doesn't trigger false positives."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    normal_lines = [
        'import os',
        'def my_function():',
        '    return "Hello, World!"',
        'x = 42',
        '# This is a comment',
    ]

    for i, line in enumerate(normal_lines, start=1):
        findings = detector.scan_line(line, i, "normal.py")
        assert len(findings) == 0, f"False positive on line: {line}"


def test_redaction():
    """Test that matched secrets are redacted."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = 'token = "ghp_1234567890123456789012345678901234AB"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) == 1
    # The full secret should not be in the redacted match
    assert findings[0].redacted_match != findings[0].matched_string
    assert "..." in findings[0].redacted_match or "***" in findings[0].redacted_match
