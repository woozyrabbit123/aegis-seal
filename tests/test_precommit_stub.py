"""Tests for pre-commit hook configuration (Sprint A5)."""

from pathlib import Path

import pytest
import yaml


def test_precommit_hooks_yaml_exists():
    """Test that .pre-commit-hooks.yaml exists in repo root."""
    hooks_file = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
    assert hooks_file.exists(), ".pre-commit-hooks.yaml should exist in repo root"


def test_precommit_hooks_yaml_valid_syntax():
    """Test that .pre-commit-hooks.yaml has valid YAML syntax."""
    hooks_file = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"

    with open(hooks_file) as f:
        data = yaml.safe_load(f)

    assert isinstance(data, list), "Root element should be a list of hooks"
    assert len(data) > 0, "Should contain at least one hook"


def test_precommit_hooks_yaml_schema():
    """Test that .pre-commit-hooks.yaml contains required fields."""
    hooks_file = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"

    with open(hooks_file) as f:
        hooks = yaml.safe_load(f)

    # Check first hook (aegis-seal-scan)
    hook = hooks[0]

    # Required fields per pre-commit schema
    assert "id" in hook, "Hook must have an id"
    assert hook["id"] == "aegis-seal-scan", "Expected hook id to be aegis-seal-scan"

    assert "name" in hook, "Hook must have a name"
    assert "entry" in hook, "Hook must have an entry point"
    assert hook["entry"] == "aegis-seal", "Entry should be aegis-seal command"

    assert "language" in hook, "Hook must specify a language"
    assert hook["language"] == "python", "Language should be python"

    assert "description" in hook, "Hook should have a description"


def test_precommit_hook_args_valid():
    """Test that hook args are valid aegis-seal commands."""
    hooks_file = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"

    with open(hooks_file) as f:
        hooks = yaml.safe_load(f)

    hook = hooks[0]

    if "args" in hook:
        args = hook["args"]
        assert isinstance(args, list), "Args should be a list"

        # First arg should be a valid command
        if len(args) > 0:
            assert args[0] in ["scan", "fix", "baseline"], \
                "First arg should be a valid aegis-seal command"


def test_precommit_hook_configuration():
    """Test hook configuration is suitable for secret scanning."""
    hooks_file = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"

    with open(hooks_file) as f:
        hooks = yaml.safe_load(f)

    hook = hooks[0]

    # Should pass filenames or scan entire repo
    assert "pass_filenames" in hook, "Should specify pass_filenames behavior"

    # Serial execution recommended for security scanning
    if "require_serial" in hook:
        assert hook["require_serial"] is True, \
            "Secret scanning should run serially to avoid race conditions"
