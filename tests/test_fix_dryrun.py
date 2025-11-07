"""Tests for LibCST auto-fix functionality."""

import tempfile
from pathlib import Path

import pytest

from aegisseal.fix.libcst_fix import apply_fixes, filter_python_findings
from aegisseal.scanning.detectors import Finding


def test_dry_run_produces_diff():
    """Test that dry run produces unified diff."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file
        test_file = tmpdir / "test.py"
        test_file.write_text('token = "ghp_1234567890123456789012345678901234AB"\n')

        # Create finding
        findings = [
            Finding(
                rule_id="AEGIS-1001",
                rule_name="GitHub Personal Access Token",
                file_path="test.py",
                line_number=1,
                line_content='token = "ghp_1234567890123456789012345678901234AB"',
                matched_string="ghp_1234567890123456789012345678901234AB",
                severity="high",
                redacted_match="ghp_1234...",
            )
        ]

        # Apply in dry-run mode
        success, output = apply_fixes(test_file, findings, dry_run=True)

        assert success
        assert output is not None
        # Should contain diff markers
        assert ("---" in output or "+++" in output) or "No replacements" in output


def test_fix_applies_with_yes_flag():
    """Test that fixes are applied when dry_run=False."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file
        test_file = tmpdir / "test.py"
        original_content = 'token = "ghp_1234567890123456789012345678901234AB"\n'
        test_file.write_text(original_content)

        # Create finding
        findings = [
            Finding(
                rule_id="AEGIS-1001",
                rule_name="GitHub Personal Access Token",
                file_path="test.py",
                line_number=1,
                line_content='token = "ghp_1234567890123456789012345678901234AB"',
                matched_string="ghp_1234567890123456789012345678901234AB",
                severity="high",
                redacted_match="ghp_1234...",
            )
        ]

        # Apply fixes
        success, output = apply_fixes(test_file, findings, dry_run=False)

        assert success

        # Read modified file
        modified_content = test_file.read_text()

        # Should contain os.getenv
        assert "os.getenv" in modified_content

        # Should not contain original secret
        assert "ghp_1234567890123456789012345678901234AB" not in modified_content


def test_os_import_added():
    """Test that 'import os' is added idempotently."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file without os import
        test_file = tmpdir / "test.py"
        test_file.write_text(
            'def main():\n'
            '    token = "ghp_1234567890123456789012345678901234AB"\n'
            '    return token\n'
        )

        findings = [
            Finding(
                rule_id="AEGIS-1001",
                rule_name="GitHub Personal Access Token",
                file_path="test.py",
                line_number=2,
                line_content='    token = "ghp_1234567890123456789012345678901234AB"',
                matched_string="ghp_1234567890123456789012345678901234AB",
                severity="high",
                redacted_match="ghp_1234...",
            )
        ]

        # Apply fixes
        success, output = apply_fixes(test_file, findings, dry_run=False)

        assert success

        # Read modified file
        modified_content = test_file.read_text()

        # Should have import os
        assert "import os" in modified_content

        # Count occurrences (should be only 1)
        assert modified_content.count("import os") == 1


def test_backup_created():
    """Test that backup file is created."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        test_file = tmpdir / "test.py"
        original_content = 'token = "ghp_1234567890123456789012345678901234AB"\n'
        test_file.write_text(original_content)

        findings = [
            Finding(
                rule_id="AEGIS-1001",
                rule_name="GitHub Personal Access Token",
                file_path="test.py",
                line_number=1,
                line_content='token = "ghp_1234567890123456789012345678901234AB"',
                matched_string="ghp_1234567890123456789012345678901234AB",
                severity="high",
                redacted_match="ghp_1234...",
            )
        ]

        # Apply fixes
        success, output = apply_fixes(test_file, findings, dry_run=False)

        assert success

        # Check backup exists
        backup_file = test_file.with_suffix(".py.bak")
        assert backup_file.exists()

        # Backup should have original content
        backup_content = backup_file.read_text()
        assert backup_content == original_content


def test_filter_python_findings():
    """Test filtering for Python files only."""
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
        ),
        Finding(
            rule_id="AEGIS-1002",
            rule_name="Test",
            file_path="test.js",
            line_number=1,
            line_content="line",
            matched_string="match",
            severity="high",
            redacted_match="...",
        ),
        Finding(
            rule_id="AEGIS-1003",
            rule_name="Test",
            file_path="config.yaml",
            line_number=1,
            line_content="line",
            matched_string="match",
            severity="high",
            redacted_match="...",
        ),
    ]

    python_findings = filter_python_findings(findings)

    # Should only include .py files
    assert len(python_findings) == 1
    assert python_findings[0].file_path == "test.py"


def test_no_crash_on_syntax_error():
    """Test that fix handles Python syntax errors gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create file with syntax error
        test_file = tmpdir / "bad.py"
        test_file.write_text('def broken(\n')  # Missing closing paren

        findings = [
            Finding(
                rule_id="AEGIS-1001",
                rule_name="Test",
                file_path="bad.py",
                line_number=1,
                line_content='def broken(',
                matched_string="broken",
                severity="high",
                redacted_match="...",
            )
        ]

        # Should not crash
        success, output = apply_fixes(test_file, findings, dry_run=True)

        assert not success  # Should fail gracefully
        assert "error" in output.lower() or "syntax" in output.lower()
