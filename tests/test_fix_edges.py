"""Tests for edge cases in LibCST fixer (Sprint A2)."""

import tempfile
from pathlib import Path

import pytest

from aegisseal.fix.libcst_fix import apply_fixes
from aegisseal.scanning.detectors import Finding


def test_fstring_literal_replacement(tmp_path):
    """Test that f-strings have only literal segments replaced."""
    code = '''
secret_key = "sk-abc123def456"
message = f"API key: sk-abc123def456 for {user}"
'''

    file_path = tmp_path / "test_fstring.py"
    file_path.write_text(code, encoding="utf-8")

    # Create findings for both occurrences
    findings = [
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=2,
            line_content='secret_key = "sk-abc123def456"',
            matched_string="sk-abc123def456",
            severity="high",
            redacted_match="sk-abc...",
        ),
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=3,
            line_content='message = f"API key: sk-abc123def456 for {user}"',
            matched_string="sk-abc123def456",
            severity="high",
            redacted_match="sk-abc...",
        ),
    ]

    # Apply fixes in dry-run mode
    success, diff = apply_fixes(file_path, findings, dry_run=True)
    assert success

    # Apply fixes for real
    success, msg = apply_fixes(file_path, findings, dry_run=False)
    assert success

    # Read the fixed code
    fixed_code = file_path.read_text(encoding="utf-8")

    # Verify f-string structure is preserved
    assert "f" in fixed_code or "f\"" in fixed_code  # Still an f-string
    assert "{user}" in fixed_code  # Expression preserved
    assert "os.getenv" in fixed_code  # Secret replaced with getenv
    assert "sk-abc123def456" not in fixed_code  # Secret removed

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_triple_quoted_string_preserved(tmp_path):
    """Test that triple-quoted strings are handled correctly."""
    code = '''
"""Module docstring."""

sql_query = """
    SELECT * FROM users
    WHERE api_key = 'sk-abc123def456'
"""
'''

    file_path = tmp_path / "test_triple.py"
    file_path.write_text(code, encoding="utf-8")

    finding = Finding(
        rule_id="AEGIS-1",
        rule_name="API Key",
        file_path=str(file_path),
        line_number=6,
        line_content="    WHERE api_key = 'sk-abc123def456'",
        matched_string="sk-abc123def456",
        severity="high",
        redacted_match="sk-abc...",
    )

    # Apply fixes
    success, msg = apply_fixes(file_path, [finding], dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # Verify module docstring is preserved
    assert '"""Module docstring."""' in fixed_code

    # Verify the secret is replaced
    assert "os.getenv" in fixed_code
    assert "sk-abc123def456" not in fixed_code

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_repeated_secrets_same_env_var(tmp_path):
    """Test that repeated secrets use the same environment variable name."""
    code = '''
key1 = "sk-abc123def456"
key2 = "sk-abc123def456"
key3 = "sk-abc123def456"
'''

    file_path = tmp_path / "test_repeated.py"
    file_path.write_text(code, encoding="utf-8")

    # Create findings for all three occurrences
    findings = [
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=2,
            line_content='key1 = "sk-abc123def456"',
            matched_string="sk-abc123def456",
            severity="high",
            redacted_match="sk-abc...",
        ),
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=3,
            line_content='key2 = "sk-abc123def456"',
            matched_string="sk-abc123def456",
            severity="high",
            redacted_match="sk-abc...",
        ),
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=4,
            line_content='key3 = "sk-abc123def456"',
            matched_string="sk-abc123def456",
            severity="high",
            redacted_match="sk-abc...",
        ),
    ]

    # Apply fixes
    success, msg = apply_fixes(file_path, findings, dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # Count occurrences of os.getenv
    getenv_count = fixed_code.count("os.getenv")
    assert getenv_count == 3, f"Expected 3 os.getenv calls, found {getenv_count}"

    # All three should use the same env var name
    # Extract the env var names
    import re

    env_vars = re.findall(r'os\.getenv\("([^"]+)"\)', fixed_code)
    assert len(env_vars) == 3
    assert env_vars[0] == env_vars[1] == env_vars[2], \
        f"Expected same env var name, got {env_vars}"

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_no_duplicate_imports(tmp_path):
    """Test that os import is added idempotently (no duplicates)."""
    code = '''
import os
import sys

secret = "sk-abc123def456"
'''

    file_path = tmp_path / "test_import.py"
    file_path.write_text(code, encoding="utf-8")

    finding = Finding(
        rule_id="AEGIS-1",
        rule_name="API Key",
        file_path=str(file_path),
        line_number=5,
        line_content='secret = "sk-abc123def456"',
        matched_string="sk-abc123def456",
        severity="high",
        redacted_match="sk-abc...",
    )

    # Apply fixes
    success, msg = apply_fixes(file_path, [finding], dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # Count import os statements
    import_count = fixed_code.count("import os")
    assert import_count == 1, f"Expected 1 'import os', found {import_count}"

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_adds_import_when_missing(tmp_path):
    """Test that os import is added when not present."""
    code = '''
secret = "sk-abc123def456"
'''

    file_path = tmp_path / "test_no_import.py"
    file_path.write_text(code, encoding="utf-8")

    finding = Finding(
        rule_id="AEGIS-1",
        rule_name="API Key",
        file_path=str(file_path),
        line_number=2,
        line_content='secret = "sk-abc123def456"',
        matched_string="sk-abc123def456",
        severity="high",
        redacted_match="sk-abc...",
    )

    # Apply fixes
    success, msg = apply_fixes(file_path, [finding], dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # Verify import was added
    assert "import os" in fixed_code

    # Verify secret was replaced
    assert "os.getenv" in fixed_code
    assert "sk-abc123def456" not in fixed_code

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_dry_run_produces_stable_diff(tmp_path):
    """Test that dry-run produces stable, deterministic diffs."""
    code = '''
key1 = "sk-abc123"
key2 = "sk-def456"
'''

    file_path = tmp_path / "test_stable.py"
    file_path.write_text(code, encoding="utf-8")

    findings = [
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=2,
            line_content='key1 = "sk-abc123"',
            matched_string="sk-abc123",
            severity="high",
            redacted_match="sk-abc...",
        ),
        Finding(
            rule_id="AEGIS-1",
            rule_name="API Key",
            file_path=str(file_path),
            line_number=3,
            line_content='key2 = "sk-def456"',
            matched_string="sk-def456",
            severity="high",
            redacted_match="sk-def...",
        ),
    ]

    # Run dry-run multiple times
    diffs = []
    for _ in range(3):
        success, diff = apply_fixes(file_path, findings, dry_run=True)
        assert success
        diffs.append(diff)

    # All diffs should be identical
    assert diffs[0] == diffs[1] == diffs[2], "Diff output should be deterministic"


def test_multiline_string_with_indentation(tmp_path):
    """Test that multiline strings with indentation are handled correctly."""
    code = '''
def get_config():
    config = """
        api_key: sk-abc123def456
        host: example.com
    """
    return config
'''

    file_path = tmp_path / "test_multiline.py"
    file_path.write_text(code, encoding="utf-8")

    finding = Finding(
        rule_id="AEGIS-1",
        rule_name="API Key",
        file_path=str(file_path),
        line_number=4,
        line_content="        api_key: sk-abc123def456",
        matched_string="sk-abc123def456",
        severity="high",
        redacted_match="sk-abc...",
    )

    # Apply fixes
    success, msg = apply_fixes(file_path, [finding], dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # Verify indentation is preserved
    assert "    config = " in fixed_code  # Function body indentation
    assert "def get_config():" in fixed_code  # Function def preserved

    # Verify secret was replaced
    assert "os.getenv" in fixed_code
    assert "sk-abc123def456" not in fixed_code

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_fstring_with_multiple_expressions(tmp_path):
    """Test f-string with multiple expressions and a secret in literal."""
    code = '''
user = "alice"
path = "/api/v1"
url = f"https://api.example.com{path}?key=sk-abc123&user={user}"
'''

    file_path = tmp_path / "test_fstring_complex.py"
    file_path.write_text(code, encoding="utf-8")

    finding = Finding(
        rule_id="AEGIS-1",
        rule_name="API Key",
        file_path=str(file_path),
        line_number=4,
        line_content='url = f"https://api.example.com{path}?key=sk-abc123&user={user}"',
        matched_string="sk-abc123",
        severity="high",
        redacted_match="sk-abc...",
    )

    # Apply fixes
    success, msg = apply_fixes(file_path, [finding], dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # Verify f-string structure preserved
    assert "{path}" in fixed_code
    assert "{user}" in fixed_code

    # Verify secret replaced
    assert "os.getenv" in fixed_code
    assert "sk-abc123" not in fixed_code

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")


def test_no_false_positives(tmp_path):
    """Test that non-secrets on the same line aren't replaced."""
    code = '''
# This is a comment with sk-abc123
normal_string = "hello world"
'''

    file_path = tmp_path / "test_false_positive.py"
    file_path.write_text(code, encoding="utf-8")

    # Finding is on line 2 (comment), but we're trying to fix line 3
    finding = Finding(
        rule_id="AEGIS-1",
        rule_name="API Key",
        file_path=str(file_path),
        line_number=2,
        line_content="# This is a comment with sk-abc123",
        matched_string="sk-abc123",
        severity="high",
        redacted_match="sk-abc...",
    )

    # Apply fixes
    success, msg = apply_fixes(file_path, [finding], dry_run=False)
    assert success

    fixed_code = file_path.read_text(encoding="utf-8")

    # The normal string on line 3 should not be affected
    assert 'normal_string = "hello world"' in fixed_code

    # Verify it compiles
    compile(fixed_code, str(file_path), "exec")
