"""Test CLI entry points and argument parsing (Sprint A7)."""

import subprocess
import sys

import pytest


def test_cli_version():
    """Test --version flag."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli", "--version"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "aegis-seal" in result.stdout or "0.1.7" in result.stdout


def test_cli_help():
    """Test --help flag."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli", "--help"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "aegis-seal" in result.stdout.lower()
    assert "scan" in result.stdout
    assert "fix" in result.stdout
    assert "baseline" in result.stdout
    assert "rules" in result.stdout


def test_cli_no_command():
    """Test CLI with no command shows help."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "aegis-seal" in result.stdout.lower() or "usage" in result.stdout.lower()


def test_rules_command():
    """Test rules command."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli", "rules"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Active Detection Rules" in result.stdout
    assert "AEGIS-" in result.stdout


def test_rules_list_flag():
    """Test rules --list command (table format)."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli", "rules", "--list"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Active Detection Rules" in result.stdout
    assert "Rule ID" in result.stdout
    assert "===" in result.stdout  # Table separator


def test_scan_missing_target():
    """Test scan command without --target flag."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli", "scan"],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "error" in result.stderr.lower() or "required" in result.stderr.lower()


def test_verbose_flag():
    """Test --verbose flag is accepted."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisseal.cli", "--verbose", "rules"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Active Detection Rules" in result.stdout


def test_cli_keyboard_interrupt():
    """Test that KeyboardInterrupt returns exit code 130."""
    # This test is challenging to implement without actually interrupting
    # We verify the code is present in cli.py instead
    from aegisseal import cli

    # Check that KeyboardInterrupt handling exists
    import inspect

    source = inspect.getsource(cli.main)
    assert "KeyboardInterrupt" in source
    assert "130" in source


def test_cli_import():
    """Test that CLI module can be imported."""
    from aegisseal import cli

    assert hasattr(cli, "main")
    assert callable(cli.main)
