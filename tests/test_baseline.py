"""Tests for baseline management."""

import tempfile
from pathlib import Path

import pytest

from aegisseal.scanning.baseline import Baseline
from aegisseal.scanning.detectors import Finding
from aegisseal.scanning.engine import ScanConfig, ScanEngine


def test_baseline_suppression():
    """Test that baseline suppresses known findings."""
    # Create a test finding
    finding = Finding(
        rule_id="AEGIS-1001",
        rule_name="Test Rule",
        file_path="test.py",
        line_number=42,
        line_content="secret = 'ghp_1234567890123456789012345678901234AB'",
        matched_string="ghp_1234567890123456789012345678901234AB",
        severity="high",
        redacted_match="ghp_1234...",
    )

    # Create baseline and add finding
    baseline = Baseline()
    baseline.add_finding(finding)

    # Check if finding is suppressed
    assert baseline.is_suppressed(finding)


def test_baseline_new_findings():
    """Test that new findings are not suppressed."""
    # Create a baseline finding
    old_finding = Finding(
        rule_id="AEGIS-1001",
        rule_name="Test Rule",
        file_path="test.py",
        line_number=42,
        line_content="secret = 'ghp_OLD1234567890123456789012345678'",
        matched_string="ghp_OLD1234567890123456789012345678",
        severity="high",
        redacted_match="ghp_OLD1...",
    )

    baseline = Baseline()
    baseline.add_finding(old_finding)

    # Create a new finding (different line)
    new_finding = Finding(
        rule_id="AEGIS-1001",
        rule_name="Test Rule",
        file_path="test.py",
        line_number=43,  # Different line
        line_content="secret = 'ghp_NEW1234567890123456789012345678'",
        matched_string="ghp_NEW1234567890123456789012345678",
        severity="high",
        redacted_match="ghp_NEW1...",
    )

    # New finding should not be suppressed
    assert not baseline.is_suppressed(new_finding)


def test_baseline_save_load():
    """Test baseline save and load."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        baseline_path = tmpdir / ".aegis.baseline"

        # Create baseline with a finding
        finding = Finding(
            rule_id="AEGIS-1001",
            rule_name="Test Rule",
            file_path="test.py",
            line_number=42,
            line_content="secret = 'ghp_1234567890123456789012345678901234AB'",
            matched_string="ghp_1234567890123456789012345678901234AB",
            severity="high",
            redacted_match="ghp_1234...",
        )

        baseline = Baseline()
        baseline.add_finding(finding)
        baseline.save(baseline_path)

        # Load baseline
        loaded_baseline = Baseline.load(baseline_path)

        # Check that finding is still suppressed
        assert loaded_baseline.is_suppressed(finding)
        assert len(loaded_baseline.entries) == 1


def test_baseline_integration():
    """Test baseline integration with scan engine."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create a test file
        test_file = tmpdir / "secrets.py"
        test_file.write_text('token = "ghp_1234567890123456789012345678901234AB"')

        # First scan to establish baseline
        config = ScanConfig(
            target_path=tmpdir,
            enable_entropy=False,
        )

        engine = ScanEngine(config)
        result1 = engine.scan()
        assert result1.total_findings > 0

        # Create baseline
        baseline = Baseline()
        for finding in result1.findings:
            baseline.add_finding(finding)

        baseline_path = tmpdir / ".aegis.baseline"
        baseline.save(baseline_path)

        # Second scan with baseline
        config2 = ScanConfig(
            target_path=tmpdir,
            enable_entropy=False,
            baseline_path=baseline_path,
        )

        engine2 = ScanEngine(config2)
        result2 = engine2.scan()

        # All findings should be suppressed
        assert result2.total_findings == 0
        assert result2.suppressed_findings == result1.total_findings


def test_baseline_change_detection():
    """Test that baseline detects when content changes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file with secret
        test_file = tmpdir / "secrets.py"
        test_file.write_text('token = "ghp_1234567890123456789012345678901234AB"')

        # First scan
        config = ScanConfig(target_path=tmpdir, enable_entropy=False)
        engine = ScanEngine(config)
        result1 = engine.scan()

        # Create baseline
        baseline = Baseline()
        for finding in result1.findings:
            baseline.add_finding(finding)

        baseline_path = tmpdir / ".aegis.baseline"
        baseline.save(baseline_path)

        # Modify the file (same line, different secret)
        test_file.write_text('token = "ghp_9999999999999999999999999999999999XX"')

        # Second scan with baseline
        config2 = ScanConfig(
            target_path=tmpdir,
            enable_entropy=False,
            baseline_path=baseline_path,
        )

        engine2 = ScanEngine(config2)
        result2 = engine2.scan()

        # Should detect new secret (different content)
        assert result2.total_findings > 0
