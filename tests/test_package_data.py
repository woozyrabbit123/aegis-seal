"""Test package data inclusion and distribution (Sprint A7)."""

import importlib.resources
from pathlib import Path

import pytest


def test_rules_yaml_accessible():
    """Test that rules YAML file is accessible from installed package."""
    # Python 3.9+ way
    try:
        if hasattr(importlib.resources, "files"):
            # Python 3.9+
            files = importlib.resources.files("aegisseal.rules")
            core_yaml = files / "core.yaml"
            assert core_yaml.is_file(), "core.yaml not found in package"
        else:
            # Python 3.7-3.8 fallback
            with importlib.resources.path("aegisseal.rules", "core.yaml") as path:
                assert path.exists(), "core.yaml not found in package"
    except Exception as e:
        pytest.fail(f"Failed to access rules YAML: {e}")


def test_rules_yaml_contents():
    """Test that rules YAML file contains expected data."""
    from aegisseal.scanning.detectors import load_default_rules

    rules = load_default_rules()

    # Should have multiple rules
    assert len(rules) > 10, "Expected more than 10 rules"

    # Check that rules have required fields
    for rule in rules:
        assert hasattr(rule, "id"), f"Rule missing id: {rule}"
        assert hasattr(rule, "name"), f"Rule missing name: {rule}"
        assert hasattr(rule, "pattern"), f"Rule missing pattern: {rule}"
        assert hasattr(rule, "severity"), f"Rule missing severity: {rule}"


def test_version_accessible():
    """Test that package version is accessible."""
    from aegisseal import __version__

    assert __version__ is not None
    assert len(__version__) > 0
    assert "0.1.7" in __version__


def test_cli_accessible():
    """Test that CLI module is accessible."""
    from aegisseal import cli

    assert hasattr(cli, "main")
    assert callable(cli.main)


def test_scanning_modules_accessible():
    """Test that scanning modules are accessible."""
    from aegisseal.scanning import baseline, detectors, engine, entropy

    # Check key classes/functions exist
    assert hasattr(engine, "ScanEngine")
    assert hasattr(detectors, "DetectorEngine")
    assert hasattr(baseline, "Baseline")
    assert hasattr(entropy, "scan_line_entropy")


def test_report_modules_accessible():
    """Test that report modules are accessible."""
    from aegisseal.report import html, json_report, sarif

    # Check key functions exist
    assert hasattr(sarif, "generate_sarif_report")
    assert hasattr(html, "generate_html_report")
    assert hasattr(json_report, "generate_json_report")


def test_fix_modules_accessible():
    """Test that fix modules are accessible."""
    from aegisseal.fix import libcst_fix

    # Check key functions exist
    assert hasattr(libcst_fix, "apply_fixes")
    assert hasattr(libcst_fix, "filter_python_findings")


def test_utils_accessible():
    """Test that utils modules are accessible."""
    from aegisseal.utils import ids, io

    # Check key functions exist
    assert hasattr(ids, "get_rule_id")
    assert hasattr(io, "read_file_lines")
    assert hasattr(io, "walk_files")


def test_manifest_in_exists():
    """Test that MANIFEST.in exists in project root."""
    manifest_path = Path(__file__).parent.parent / "MANIFEST.in"
    assert manifest_path.exists(), "MANIFEST.in not found in project root"

    # Read and verify contents
    content = manifest_path.read_text()
    assert "README.md" in content
    assert "LICENSE" in content
    assert "rules" in content.lower()
    assert "*.yaml" in content


def test_pyproject_toml_metadata():
    """Test that pyproject.toml has proper metadata."""
    try:
        import tomli
    except ImportError:
        pytest.skip("tomli not available")

    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml not found"

    with open(pyproject_path, "rb") as f:
        data = tomli.load(f)

    # Check project metadata
    assert "project" in data
    project = data["project"]

    assert project["name"] == "aegis-seal"
    assert project["version"] == "0.1.7"
    assert "description" in project
    assert "readme" in project
    assert "license" in project
    assert "authors" in project
    assert "requires-python" in project
    assert "dependencies" in project

    # Check URLs
    assert "urls" in project or "project.urls" in data
    if "urls" in project:
        assert "Homepage" in project["urls"]
        assert "Repository" in project["urls"]

    # Check classifiers
    assert "classifiers" in project
    assert len(project["classifiers"]) > 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
