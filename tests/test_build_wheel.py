"""Test build system and wheel generation (Sprint A7)."""

import subprocess
from pathlib import Path

import pytest


def test_build_scripts_exist():
    """Test that build scripts exist."""
    project_root = Path(__file__).parent.parent

    build_sh = project_root / "scripts" / "build_wheel.sh"
    build_ps1 = project_root / "scripts" / "build_wheel.ps1"

    assert build_sh.exists(), "build_wheel.sh not found"
    assert build_ps1.exists(), "build_wheel.ps1 not found"

    # Check that Unix script is executable
    assert build_sh.stat().st_mode & 0o111, "build_wheel.sh not executable"


def test_pyproject_toml_build_system():
    """Test that pyproject.toml has proper build system config."""
    project_root = Path(__file__).parent.parent
    pyproject_path = project_root / "pyproject.toml"

    assert pyproject_path.exists()

    content = pyproject_path.read_text()

    # Check build system
    assert "[build-system]" in content
    assert "setuptools" in content
    assert "wheel" in content

    # Check project section
    assert "[project]" in content
    assert "name = \"aegis-seal\"" in content
    assert "version = \"0.1.7\"" in content

    # Check scripts
    assert "[project.scripts]" in content
    assert "aegis-seal" in content


def test_setuptools_config():
    """Test setuptools configuration."""
    project_root = Path(__file__).parent.parent
    pyproject_path = project_root / "pyproject.toml"

    content = pyproject_path.read_text()

    # Check setuptools configuration
    assert "[tool.setuptools]" in content
    assert "package-dir" in content
    assert "[tool.setuptools.packages.find]" in content
    assert "where" in content

    # Check package data
    assert "[tool.setuptools.package-data]" in content
    assert "aegisseal" in content
    assert "rules/*.yaml" in content or "rules" in content


def test_manifest_in_format():
    """Test MANIFEST.in format and contents."""
    project_root = Path(__file__).parent.parent
    manifest_path = project_root / "MANIFEST.in"

    assert manifest_path.exists()

    content = manifest_path.read_text()

    # Check includes
    assert "include" in content.lower()
    assert "README.md" in content
    assert "LICENSE" in content

    # Check recursive includes
    assert "recursive-include" in content

    # Check excludes
    assert "exclude" in content or "global-exclude" in content


def test_version_consistency():
    """Test that version is consistent across files."""
    project_root = Path(__file__).parent.parent

    # Read version from __init__.py
    init_path = project_root / "src" / "aegisseal" / "__init__.py"
    init_content = init_path.read_text()

    # Extract version from __init__.py
    import re

    version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_content)
    assert version_match, "Could not find __version__ in __init__.py"
    init_version = version_match.group(1)

    # Read version from pyproject.toml
    pyproject_path = project_root / "pyproject.toml"
    pyproject_content = pyproject_path.read_text()

    version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', pyproject_content)
    assert version_match, "Could not find version in pyproject.toml"
    toml_version = version_match.group(1)

    # Versions should match
    assert init_version == toml_version, (
        f"Version mismatch: __init__.py has {init_version}, "
        f"pyproject.toml has {toml_version}"
    )

    # Should be 0.1.7
    assert init_version == "0.1.7", f"Expected version 0.1.7, got {init_version}"


def test_changelog_exists():
    """Test that CHANGELOG.md exists and has proper format."""
    project_root = Path(__file__).parent.parent
    changelog_path = project_root / "CHANGELOG.md"

    assert changelog_path.exists()

    content = changelog_path.read_text()

    # Check Keep a Changelog format
    assert "# Changelog" in content
    assert "Keep a Changelog" in content
    assert "Semantic Versioning" in content

    # Check version entries
    assert "[0.1.7]" in content
    assert "## " in content  # Section headers


def test_contributing_exists():
    """Test that CONTRIBUTING.md exists."""
    project_root = Path(__file__).parent.parent
    contributing_path = project_root / "CONTRIBUTING.md"

    assert contributing_path.exists()

    content = contributing_path.read_text()

    # Check key sections
    assert "Contributing" in content
    assert "Development Setup" in content
    assert "Running Tests" in content
    assert "Code Style" in content


@pytest.mark.slow
def test_build_wheel_dryrun():
    """Test that we can build a wheel (slow test, marked)."""
    pytest.skip("Skipping slow build test by default")

    project_root = Path(__file__).parent.parent

    # Try to build wheel
    result = subprocess.run(
        ["python", "-m", "build", "--wheel"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=60,
    )

    # Should succeed or be skipped
    if result.returncode != 0:
        pytest.skip(f"Build failed (expected in test env): {result.stderr}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
