"""Tests for CLI hook and action commands (Sprint A5)."""

import subprocess
import tempfile
from pathlib import Path

import pytest


def test_hook_install_command():
    """Test that hook --install command outputs expected configuration."""
    result = subprocess.run(
        ["python", "-m", "aegisseal.cli", "hook", "--install"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Should succeed
    assert result.returncode == 0, f"Command failed: {result.stderr}"

    # Should mention pre-commit config
    output = result.stdout
    assert "pre-commit" in output.lower(), "Should mention pre-commit"
    assert "aegis-seal" in output.lower() or "created" in output.lower(), \
        "Should reference aegis-seal or indicate creation"


def test_hook_install_creates_config():
    """Test that hook --install creates .pre-commit-config.yaml when it doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Run command in temp directory
        result = subprocess.run(
            ["python", "-m", "aegisseal.cli", "hook", "--install"],
            capture_output=True,
            text=True,
            cwd=tmpdir,
        )

        # Should succeed
        assert result.returncode == 0

        # Should create config file
        config_file = tmpdir / ".pre-commit-config.yaml"
        assert config_file.exists(), ".pre-commit-config.yaml should be created"

        # Config should contain aegis-seal
        content = config_file.read_text()
        assert "aegis-seal" in content


def test_hook_install_with_existing_config():
    """Test that hook --install warns when .pre-commit-config.yaml exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create existing config
        config_file = tmpdir / ".pre-commit-config.yaml"
        config_file.write_text("# Existing config\n")

        # Run command
        result = subprocess.run(
            ["python", "-m", "aegisseal.cli", "hook", "--install"],
            capture_output=True,
            text=True,
            cwd=tmpdir,
        )

        # Should succeed
        assert result.returncode == 0

        # Should warn about existing file
        output = result.stdout
        assert "already exists" in output.lower() or "add" in output.lower(), \
            "Should warn about existing config"


def test_action_example_command():
    """Test that action --example command outputs valid workflow YAML."""
    result = subprocess.run(
        ["python", "-m", "aegisseal.cli", "action", "--example"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Should succeed
    assert result.returncode == 0, f"Command failed: {result.stderr}"

    # Should output YAML
    output = result.stdout
    assert "name:" in output, "Should output YAML with name field"
    assert "on:" in output, "Should specify workflow triggers"
    assert "jobs:" in output, "Should define jobs"
    assert "steps:" in output, "Should include steps"


def test_action_example_includes_aegis_seal():
    """Test that action --example output includes Aegis Seal action."""
    result = subprocess.run(
        ["python", "-m", "aegisseal.cli", "action", "--example"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    output = result.stdout

    # Should reference aegis-seal
    assert "aegis-seal" in output.lower(), "Should reference aegis-seal"

    # Should use the action
    assert "uses:" in output, "Should use GitHub Actions syntax"

    # Should mention checkout
    assert "checkout" in output.lower(), "Should include checkout step"


def test_action_example_valid_yaml_syntax():
    """Test that action --example outputs syntactically valid YAML."""
    import yaml

    result = subprocess.run(
        ["python", "-m", "aegisseal.cli", "action", "--example"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Should be valid YAML
    try:
        workflow = yaml.safe_load(result.stdout)
        assert isinstance(workflow, dict), "Should parse as YAML dict"
        assert "name" in workflow, "Should have workflow name"
        # Note: YAML parses "on:" as boolean True, so check for either
        assert "on" in workflow or True in workflow, "Should have triggers"
        assert "jobs" in workflow, "Should have jobs"
    except yaml.YAMLError as e:
        pytest.fail(f"Output is not valid YAML: {e}")


def test_hook_command_without_args():
    """Test that hook command without args shows usage."""
    result = subprocess.run(
        ["python", "-m", "aegisseal.cli", "hook"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Should fail or show usage
    assert result.returncode != 0 or "usage" in result.stdout.lower(), \
        "Should show usage when no args provided"


def test_action_command_without_args():
    """Test that action command without args shows usage."""
    result = subprocess.run(
        ["python", "-m", "aegisseal.cli", "action"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Should fail or show usage
    assert result.returncode != 0 or "usage" in result.stdout.lower(), \
        "Should show usage when no args provided"
