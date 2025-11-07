# Contributing to Aegis Seal

Thank you for your interest in contributing to Aegis Seal! This document provides guidelines and instructions for setting up your development environment and contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Adding Detection Rules](#adding-detection-rules)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/aegis-seal.git
   cd aegis-seal
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/your-org/aegis-seal.git
   ```

## Development Setup

### Prerequisites

- Python 3.11 or higher
- pip (Python package installer)
- git

### Install Development Dependencies

```bash
# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install package in editable mode with dev dependencies
pip install -e ".[dev]"
```

This will install:
- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `ruff` - Linting and formatting

### Verify Installation

```bash
# Check that aegis-seal CLI is available
aegis-seal --version

# Run the test suite
pytest tests/ -v
```

## Running Tests

### Run All Tests

```bash
pytest tests/ -v
```

### Run Tests with Coverage

```bash
pytest tests/ --cov=aegisseal --cov-report=html --cov-report=term
```

Coverage reports will be generated in `htmlcov/index.html`.

### Run Specific Test Files

```bash
# Run only CLI tests
pytest tests/test_cli.py -v

# Run only detection tests
pytest tests/test_detectors.py -v
```

### Run Tests in Parallel (faster)

```bash
pip install pytest-xdist
pytest tests/ -n auto
```

## Code Style

Aegis Seal uses [Ruff](https://github.com/astral-sh/ruff) for linting and formatting.

### Check Code Style

```bash
ruff check src/ tests/
```

### Auto-fix Style Issues

```bash
ruff check --fix src/ tests/
```

### Configuration

Code style configuration is in `pyproject.toml`:
- Line length: 100 characters
- Target version: Python 3.11+
- Selected rules: E, F, I, N, W, UP

## Adding Detection Rules

Detection rules are defined in `src/aegisseal/rules/core.yaml`.

### Rule Format

```yaml
- id: rule_id
  name: Human-readable Rule Name
  pattern: 'regex_pattern_here'
  severity: high|medium|low|critical
  context_hints:
    - example
    - test
  allowlist:
    - 'known_false_positive_value'
  description: Description of what this rule detects
```

### Guidelines for Rules

1. **Use MIT/Apache Licensed Sources Only**
   - Only add patterns from MIT or Apache 2.0 licensed projects
   - Document the source in PR description

2. **Test Your Rule**
   - Add test cases in `tests/test_detectors.py`
   - Include both positive (should match) and negative (should not match) cases

3. **Minimize False Positives**
   - Use context hints to reduce false positives
   - Add known safe values to allowlist
   - Test against real codebases

4. **Document the Pattern**
   - Provide clear description
   - Include examples in test cases

### Example Rule Addition

```python
# In tests/test_detectors.py
def test_new_secret_detection():
    """Test detection of NewSecret tokens."""
    line = 'token = "ns_1234567890abcdef"'
    findings = scan_line_for_secrets(line, 1, "test.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "AEGIS-XXXX"
    assert findings[0].severity == "high"
```

## Submitting Changes

### Branch Naming

Use descriptive branch names:
- `feat/short-description` - New features
- `fix/short-description` - Bug fixes
- `docs/short-description` - Documentation updates
- `test/short-description` - Test additions/fixes

### Commit Messages

Follow conventional commit format:

```
type(scope): short description

Longer description if needed

- Bullet points for details
- More details
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/fixes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build/tooling changes

Example:
```
feat(rules): add detection for DigitalOcean API tokens

- Add pattern for DigitalOcean personal access tokens
- Include context hints for false positive reduction
- Add test cases for validation
```

### Pull Request Process

1. **Update your branch** with latest upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests** and ensure they pass:
   ```bash
   pytest tests/ -v
   ruff check src/ tests/
   ```

3. **Update documentation** if needed:
   - Update README.md for user-facing changes
   - Update CHANGELOG.md following Keep a Changelog format
   - Add docstrings to new functions

4. **Create Pull Request**:
   - Provide clear title and description
   - Reference any related issues (Fixes #123)
   - Include test results
   - Add screenshots for UI changes (if applicable)

5. **Address Review Feedback**:
   - Respond to comments
   - Make requested changes
   - Keep discussions constructive

## Release Process

Releases are managed by project maintainers.

### Version Numbering

Aegis Seal follows [Semantic Versioning](https://semver.org/):
- MAJOR.MINOR.PATCH (e.g., 0.1.7)
- Increment PATCH for bug fixes
- Increment MINOR for new features
- Increment MAJOR for breaking changes

### Creating a Release

1. Update version in:
   - `src/aegisseal/__init__.py`
   - `pyproject.toml`

2. Update `CHANGELOG.md`:
   - Move unreleased changes to new version section
   - Add release date

3. Build and test:
   ```bash
   # Build wheel
   python -m build

   # Test installation
   pip install dist/aegis_seal-X.Y.Z-py3-none-any.whl

   # Run tests
   pytest tests/ -v
   ```

4. Create git tag:
   ```bash
   git tag -a v0.1.7 -m "Release v0.1.7"
   git push origin v0.1.7
   ```

5. Publish to PyPI:
   ```bash
   python -m twine upload dist/*
   ```

## Development Tips

### Debugging

Enable verbose output:
```bash
aegis-seal scan --target . --verbose
```

### Testing Against Real Projects

```bash
# Test on popular open-source projects
git clone https://github.com/example/project
aegis-seal scan --target project/ --format json
```

### Performance Profiling

```bash
python -m cProfile -o profile.stats -m aegisseal.cli scan --target .
python -m pstats profile.stats
```

## Questions or Issues?

- Open an issue on GitHub: https://github.com/your-org/aegis-seal/issues
- Check existing issues and discussions first
- Provide as much context as possible (OS, Python version, commands run, error messages)

## License

By contributing to Aegis Seal, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Aegis Seal!
