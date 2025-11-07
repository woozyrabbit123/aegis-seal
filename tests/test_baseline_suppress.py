"""Tests for baseline suppression and inline ignore comments (Sprint A4)."""

import json
import tempfile
from pathlib import Path

import pytest

from aegisseal.scanning.baseline import Baseline
from aegisseal.scanning.detectors import Finding
from aegisseal.scanning.engine import ScanConfig, ScanEngine
from aegisseal.scanning.suppression import is_suppressed_by_comment, parse_suppression_comment


@pytest.fixture
def temp_test_dir(tmp_path):
    """Create a temporary test directory."""
    return tmp_path


def test_baseline_load_and_write_roundtrip(temp_test_dir):
    """Test that baseline can be written and loaded back identically."""
    baseline_path = temp_test_dir / ".aegis.baseline"

    # Create baseline with some findings
    findings = [
        Finding(
            rule_id="AEGIS-1001",
            rule_name="GitHub PAT",
            file_path="test1.py",
            line_number=10,
            line_content='token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"',
            matched_string="ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            severity="high",
            redacted_match="ghp_1234...",
        ),
        Finding(
            rule_id="AEGIS-1100",
            rule_name="AWS Access Key",
            file_path="test2.py",
            line_number=5,
            line_content='aws_key = "AKIAIOSFODNN7EXAMPLE"',
            matched_string="AKIAIOSFODNN7EXAMPLE",
            severity="high",
            redacted_match="AKIAI...",
        ),
    ]

    # Save baseline
    baseline = Baseline()
    for finding in findings:
        baseline.add_finding(finding)
    baseline.save(baseline_path)

    # Load baseline
    loaded_baseline = Baseline.load(baseline_path)

    # Verify counts match
    assert len(loaded_baseline.entries) == len(findings)

    # Verify all findings are recognized as suppressed
    for finding in findings:
        assert loaded_baseline.is_suppressed(finding)


def test_match_in_baseline_skips_known(temp_test_dir):
    """Test that findings in baseline are correctly identified."""
    finding = Finding(
        rule_id="AEGIS-1001",
        rule_name="GitHub PAT",
        file_path="test.py",
        line_number=10,
        line_content='token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"',
        matched_string="ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        severity="high",
        redacted_match="ghp_1234...",
    )

    baseline = Baseline()
    baseline.add_finding(finding)

    # Same finding should be suppressed
    assert baseline.is_suppressed(finding)

    # Different finding should not be suppressed
    different_finding = Finding(
        rule_id="AEGIS-1100",
        rule_name="AWS Access Key",
        file_path="test2.py",
        line_number=5,
        line_content='aws_key = "AKIAIOSFODNN7EXAMPLE"',
        matched_string="AKIAIOSFODNN7EXAMPLE",
        severity="high",
        redacted_match="AKIAI...",
    )
    assert not baseline.is_suppressed(different_finding)


def test_update_baseline_merges_and_sorts(temp_test_dir):
    """Test that baseline update merges and sorts entries deterministically."""
    baseline_path = temp_test_dir / ".aegis.baseline"

    # Create initial baseline
    finding1 = Finding(
        rule_id="AEGIS-1001",
        rule_name="Test",
        file_path="b.py",
        line_number=20,
        line_content="secret1",
        matched_string="secret1",
        severity="high",
        redacted_match="...",
    )

    baseline = Baseline()
    baseline.add_finding(finding1)
    baseline.save(baseline_path)

    # Load and add more findings
    baseline2 = Baseline.load(baseline_path)
    finding2 = Finding(
        rule_id="AEGIS-1002",
        rule_name="Test",
        file_path="a.py",
        line_number=10,
        line_content="secret2",
        matched_string="secret2",
        severity="high",
        redacted_match="...",
    )
    finding3 = Finding(
        rule_id="AEGIS-1003",
        rule_name="Test",
        file_path="b.py",
        line_number=15,
        line_content="secret3",
        matched_string="secret3",
        severity="high",
        redacted_match="...",
    )

    baseline2.merge([finding2, finding3])
    baseline2.save(baseline_path)

    # Verify all 3 findings are in baseline
    assert len(baseline2.entries) == 3

    # Verify sorting: should be sorted by (file, line, rule)
    # Expected order: a.py:10, b.py:15, b.py:20
    assert baseline2.entries[0].file_path == "a.py"
    assert baseline2.entries[0].line_number == 10

    assert baseline2.entries[1].file_path == "b.py"
    assert baseline2.entries[1].line_number == 15

    assert baseline2.entries[2].file_path == "b.py"
    assert baseline2.entries[2].line_number == 20


def test_inline_ignore_comment_skips_line():
    """Test that inline ignore comments suppress specific rules."""
    # Single rule suppression
    line = 'secret = "ghp_abc123"  # aegis: ignore=AEGIS-1001'
    assert is_suppressed_by_comment(line, "AEGIS-1001")
    assert not is_suppressed_by_comment(line, "AEGIS-1002")

    # Case-insensitive
    line2 = 'secret = "ghp_abc123"  # AEGIS: IGNORE=AEGIS-1001'
    assert is_suppressed_by_comment(line2, "AEGIS-1001")

    # Space variations
    line3 = 'secret = "ghp_abc123"  # aegis:ignore=AEGIS-1001'
    assert is_suppressed_by_comment(line3, "AEGIS-1001")


def test_inline_multiple_ids():
    """Test that inline comments can suppress multiple rule IDs."""
    line = 'secret = "test"  # aegis: ignore=AEGIS-1001,AEGIS-1002'

    assert is_suppressed_by_comment(line, "AEGIS-1001")
    assert is_suppressed_by_comment(line, "AEGIS-1002")
    assert not is_suppressed_by_comment(line, "AEGIS-1003")


def test_new_line_breaks_suppression(temp_test_dir):
    """Test that editing a line changes its hash and breaks baseline suppression."""
    # Create a test file
    test_file = temp_test_dir / "test.py"
    test_file.write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n')

    # Scan and create baseline
    config = ScanConfig(target_path=temp_test_dir, enable_entropy=False)
    engine = ScanEngine(config)
    result1 = engine.scan()

    # Should find 1 secret
    assert result1.total_findings >= 1

    # Create baseline
    baseline = Baseline()
    for finding in result1.findings:
        baseline.add_finding(finding)

    baseline_path = temp_test_dir / ".aegis.baseline"
    baseline.save(baseline_path)

    # Scan again with baseline - should suppress
    config2 = ScanConfig(target_path=temp_test_dir, baseline_path=baseline_path)
    engine2 = ScanEngine(config2)
    result2 = engine2.scan()

    assert result2.total_findings == 0
    assert result2.suppressed_findings >= 1

    # Edit the line (changing hash)
    test_file.write_text('token  = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # extra space\n')

    # Scan again - should NOT be suppressed anymore
    config3 = ScanConfig(target_path=temp_test_dir, baseline_path=baseline_path)
    engine3 = ScanEngine(config3)
    result3 = engine3.scan()

    # Should find the secret again because line changed
    assert result3.total_findings >= 1


def test_scan_with_baseline_counts_correctly(temp_test_dir):
    """Test that scan correctly counts total vs suppressed findings."""
    # Create test files with secrets
    file1 = temp_test_dir / "file1.py"
    file1.write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n')

    file2 = temp_test_dir / "file2.py"
    file2.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')

    # First scan without baseline
    config1 = ScanConfig(target_path=temp_test_dir, enable_entropy=False)
    engine1 = ScanEngine(config1)
    result1 = engine1.scan()

    total_secrets = result1.total_findings
    assert total_secrets >= 1, "Should find at least one secret"

    # Create baseline with all findings
    baseline = Baseline()
    for finding in result1.findings:
        baseline.add_finding(finding)

    baseline_path = temp_test_dir / ".aegis.baseline"
    baseline.save(baseline_path)

    # Scan with baseline
    config2 = ScanConfig(target_path=temp_test_dir, baseline_path=baseline_path)
    engine2 = ScanEngine(config2)
    result2 = engine2.scan()

    # All findings should be suppressed
    assert result2.total_findings == 0, "All findings should be suppressed by baseline"
    assert result2.suppressed_findings == total_secrets, "Suppressed count should match original"


def test_idempotent_baseline_update(temp_test_dir):
    """Test that updating baseline multiple times with same findings is idempotent."""
    # Create test file
    test_file = temp_test_dir / "test.py"
    test_file.write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n')

    # Scan and create baseline
    config = ScanConfig(target_path=temp_test_dir, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    baseline = Baseline()
    baseline.merge(result.findings)

    baseline_path = temp_test_dir / ".aegis.baseline"
    baseline.save(baseline_path)

    # Read baseline content
    with open(baseline_path) as f:
        content1 = f.read()

    # Update baseline again with same findings
    baseline2 = Baseline.load(baseline_path)
    baseline2.merge(result.findings)
    baseline2.save(baseline_path)

    # Read baseline content again
    with open(baseline_path) as f:
        content2 = f.read()

    # Should be byte-identical
    assert content1 == content2


def test_no_raw_values_in_baseline(temp_test_dir):
    """Test that baseline file never contains raw secret values."""
    # Create test file with a secret
    test_file = temp_test_dir / "test.py"
    secret_value = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    test_file.write_text(f'token = "{secret_value}"\n')

    # Scan and create baseline
    config = ScanConfig(target_path=temp_test_dir, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    baseline = Baseline()
    baseline.merge(result.findings)

    baseline_path = temp_test_dir / ".aegis.baseline"
    baseline.save(baseline_path)

    # Read baseline file as text
    with open(baseline_path) as f:
        baseline_content = f.read()

    # Verify secret value is NOT in baseline file
    assert secret_value not in baseline_content

    # Verify it's valid JSON
    baseline_data = json.loads(baseline_content)

    # Verify structure
    assert "version" in baseline_data
    assert "entries" in baseline_data
    assert len(baseline_data["entries"]) > 0

    # Verify each entry has hash but not raw value
    for entry in baseline_data["entries"]:
        assert "hash" in entry
        assert "file" in entry
        assert "line" in entry
        assert "rule" in entry
        # Should not contain raw secret value
        assert secret_value not in json.dumps(entry)


def test_inline_suppression_with_scan(temp_test_dir):
    """Test that inline suppression comments work during scanning."""
    # Create test file with inline suppression
    test_file = temp_test_dir / "test.py"
    test_file.write_text(
        'token1 = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # aegis: ignore=AEGIS-1001\n'
        'token2 = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'  # No suppression
    )

    # Scan without baseline
    config = ScanConfig(target_path=temp_test_dir, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    # Should find only token2 (token1 is suppressed by inline comment)
    assert result.total_findings >= 1

    # Verify token1 is not in findings
    for finding in result.findings:
        assert "token1" not in finding.line_content


def test_parse_suppression_comment():
    """Test the suppression comment parser directly."""
    # Valid formats
    assert parse_suppression_comment("# aegis: ignore=AEGIS-1001") == {"AEGIS-1001"}
    assert parse_suppression_comment("# aegis:ignore=AEGIS-1001") == {"AEGIS-1001"}
    assert parse_suppression_comment("# AEGIS: IGNORE=AEGIS-1001") == {"AEGIS-1001"}
    assert parse_suppression_comment("# aegis: ignore=AEGIS-1001,AEGIS-1002") == {
        "AEGIS-1001",
        "AEGIS-1002",
    }

    # Case normalization
    assert parse_suppression_comment("# aegis: ignore=aegis-1001") == {"AEGIS-1001"}

    # No suppression comment
    assert parse_suppression_comment("# regular comment") is None
    assert parse_suppression_comment("token = 'secret'") is None

    # Malformed
    assert parse_suppression_comment("# aegis: ignore=") is None
