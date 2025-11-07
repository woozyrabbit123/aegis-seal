# 🛡️ Aegis Seal

**Local-first secret scanner with auto-fix capabilities**

Aegis Seal is a fast, offline secret scanner designed to detect hardcoded secrets in your codebase and automatically fix them. It supports multiple output formats including SARIF 2.1.0 for seamless integration with security tools.

## ✨ Features

- 🔒 **Local-first**: No network calls, all scanning happens offline
- 🎯 **Regex-based detection**: Fast and accurate pattern matching for 19+ secret types
- ⚡ **Optional entropy scanning**: Detect high-entropy strings (opt-in with `--enable-entropy`)
- 🔧 **Auto-fix**: LibCST-based Python code transformation to replace secrets with `os.getenv()`
- 📊 **Multiple report formats**: JSON, SARIF 2.1.0, and single-file HTML with dark mode
- 🗂️ **Baseline management**: Suppress known/approved findings with `.aegis.baseline`
- 🎨 **Deterministic output**: Stable rule IDs and consistent ordering
- 🚀 **CI-ready**: Easy integration with GitHub Actions and other CI systems

## 📦 Installation

### From PyPI (when published)

```bash
pip install aegis-seal
```

### From source

```bash
git clone https://github.com/your-org/aegis-seal.git
cd aegis-seal
pip install -e .
```

### For development

```bash
pip install -e ".[dev]"
```

## 🚀 Quick Start

### Scan for secrets

```bash
# Scan current directory with all report formats
aegis-seal scan --target . --format all --output reports/

# Scan specific directory with JSON output only
aegis-seal scan --target /path/to/project --format json

# Enable entropy-based detection (opt-in)
aegis-seal scan --target . --enable-entropy
```

### Auto-fix secrets in Python files

```bash
# Dry-run (preview changes)
aegis-seal fix --target .

# Apply fixes
aegis-seal fix --target . --yes

# Fix only specific rule
aegis-seal fix --target . --rule AEGIS-1001 --yes
```

### Manage baseline

```bash
# Create/update baseline with current findings
aegis-seal baseline --target . --update

# View baseline info
aegis-seal baseline --target .
```

### List detection rules

```bash
aegis-seal rules
```

## 📋 Detection Rules

Aegis Seal includes 19 built-in detection rules covering:

| Rule ID | Name | Severity |
|---------|------|----------|
| AEGIS-1001 | GitHub Personal Access Token | High |
| AEGIS-1002 | GitHub OAuth Access Token | High |
| AEGIS-1003 | GitHub App Token | High |
| AEGIS-1004 | GitHub Refresh Token | High |
| AEGIS-1100 | AWS Access Key ID | High |
| AEGIS-1101 | AWS Secret Access Key | Critical |
| AEGIS-1102 | AWS Session Token | High |
| AEGIS-1200 | Generic Private Key | Critical |
| AEGIS-1201 | RSA Private Key | Critical |
| AEGIS-1202 | SSH Private Key | Critical |
| AEGIS-1203 | PGP Private Key | Critical |
| AEGIS-1300 | Slack Token | High |
| AEGIS-1301 | Slack Webhook URL | High |
| AEGIS-1400 | Stripe API Key | Critical |
| AEGIS-1500 | Google API Key | High |
| AEGIS-1501 | Google OAuth Token | High |
| AEGIS-1600 | Azure Client Secret | High |
| AEGIS-1700 | JWT Token | Medium |
| AEGIS-1800 | Generic API Key | Medium |

### Rule sources

All detection patterns are derived from MIT/Apache licensed sources:
- [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT)
- [detect-secrets](https://github.com/Yelp/detect-secrets) (Apache 2.0)
- [Secrets-Patterns-DB](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0)

## 🔧 Auto-fix

Aegis Seal can automatically fix secrets in Python files using LibCST:

**Before:**
```python
# app.py
GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
```

**After:**
```python
# app.py
import os

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
```

### Features:
- ✅ Idempotent `import os` addition
- ✅ Intelligent environment variable naming
- ✅ Backup files created automatically (`.bak`)
- ✅ Dry-run preview with unified diff
- ✅ Safe: only applies when explicitly requested with `--yes`

## 📊 Report Formats

### JSON Report

```json
{
  "version": "0.1.0",
  "summary": {
    "total_findings": 5,
    "scanned_files": 10,
    "by_severity": {
      "critical": 2,
      "high": 3,
      "medium": 0,
      "low": 0
    }
  },
  "findings": [...]
}
```

### SARIF 2.1.0 Report

Fully compliant with [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html):
- ✅ Deterministic rule IDs
- ✅ Fingerprints for deduplication
- ✅ Security severity scores
- ✅ Rich rule descriptions

Perfect for integration with:
- GitHub Code Scanning
- Azure DevOps
- GitLab Security Dashboard
- Any SARIF-compatible tool

### HTML Report

Single-file HTML report with:
- 🌙 Dark mode by default
- 🔍 Client-side filtering by severity
- 📊 Summary statistics
- 💻 No external dependencies (inline CSS/JS)

## 🗂️ Baseline Management & Suppression

### Baseline Files

Suppress known/approved findings using `.aegis.baseline`:

```bash
# Create baseline (approve current findings)
aegis-seal baseline --target . --update

# Future scans will only report new secrets
aegis-seal scan --target .

# Merge new findings into existing baseline
aegis-seal baseline --target . --update  # idempotent
```

The baseline uses:
- ✅ Hash-based matching (no raw secrets stored)
- ✅ File path, line number, and rule ID
- ✅ Content-aware (detects when secrets change)
- ✅ Deterministic sorting for version control
- ✅ Idempotent updates (safe to run multiple times)

**Important:** Baseline stores only hashes, never raw secret values.

### Inline Suppression Comments

Suppress specific findings directly in code:

```python
# Single rule suppression
token = "ghp_abc123"  # aegis: ignore=AEGIS-1001

# Multiple rules
secret = "test"  # aegis: ignore=AEGIS-1001,AEGIS-1002

# Case-insensitive, space-flexible
api_key = "sk-test"  # AEGIS: IGNORE=AEGIS-1800
```

Inline suppression is:
- ✅ Line-scoped only (doesn't affect other lines)
- ✅ Case-insensitive
- ✅ Supports comma-separated rule IDs
- ✅ Works for all file types

### Example Workflow

```bash
# 1. Initial scan
aegis-seal scan --target src/ --format all

# 2. Review findings and approve known secrets
aegis-seal baseline --target src/ --update

# 3. Add inline suppressions for specific cases
# (edit code to add # aegis: ignore=RULE-ID comments)

# 4. Scan again - only new issues reported
aegis-seal scan --target src/

# 5. Fix remaining secrets
aegis-seal fix --target src/ --yes
```

## ⚙️ Configuration

### Exclude patterns

```bash
aegis-seal scan --target . --exclude "vendor/**,*.lock"
```

### Custom baseline path

```bash
aegis-seal scan --target . --baseline /path/to/.baseline
```

### Entropy thresholds

Entropy scanning is **opt-in**. When enabled, it uses conservative thresholds:
- High entropy: ≥4.5 bits/char
- Medium entropy: ≥4.0 bits/char
- Minimum length: 20 characters

## 🚀 Adoption & Integration

### Pre-commit Hook

Catch secrets before they're committed:

```bash
# Install pre-commit configuration
aegis-seal hook --install

# Install pre-commit framework
pip install pre-commit

# Install the git hooks
pre-commit install

# Test it
pre-commit run --all-files
```

**Manual setup:** Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/woozyrabbit123/aegis-seal
    rev: main  # or specify a version tag
    hooks:
      - id: aegis-seal-scan
```

### GitHub Actions

**Quick setup:**

```bash
# Generate example workflow
aegis-seal action --example > .github/workflows/aegis.yml
```

**Example workflow:**

```yaml
name: Aegis Seal Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  secret-scan:
    name: Scan for Secrets
    runs-on: ubuntu-latest

    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Aegis Seal
        uses: woozyrabbit123/aegis-seal/contrib/github-action@main
        with:
          target: src/
          upload-sarif: true
```

**Features:**
- ✅ Automatic SARIF upload to GitHub Security
- ✅ Supports pull request annotations
- ✅ Configurable target path
- ✅ Optional SARIF upload control

### GitLab CI

```yaml
secret-scan:
  image: python:3.11
  script:
    - pip install aegis-seal
    - aegis-seal scan --target . --format sarif --output reports/
  artifacts:
    reports:
      sast: reports/scan.sarif
```

### Other CI Systems

For Jenkins, CircleCI, Travis CI, or any CI system:

```bash
# Install
pip install aegis-seal

# Scan and output SARIF
aegis-seal scan --target . --format sarif --output reports/

# Check exit code (0 = no secrets found)
```

### Local-First Philosophy

Aegis Seal runs entirely **offline** with **zero network calls**:
- ✅ No data leaves your machine
- ✅ Works in air-gapped environments
- ✅ Fast: no API rate limits
- ✅ Privacy-focused: secrets never transmitted

## 🧪 Testing

Run the test suite:

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=aegisseal --cov-report=html
```

All 39 tests should pass:
- ✅ Regex detection tests
- ✅ Entropy scanning tests (opt-in verification)
- ✅ Baseline management tests
- ✅ SARIF 2.1.0 compliance tests
- ✅ HTML report tests
- ✅ LibCST auto-fix tests

## 🎯 Design Principles

1. **Local-first**: No network I/O in core scanning
2. **Deterministic**: Stable rule IDs and consistent output
3. **Safe by default**: Entropy scanning opt-in, fix requires `--yes`
4. **License-compliant**: Only MIT/Apache rule sources
5. **CI-ready**: SARIF 2.1.0 for seamless integration

## 📝 Project Structure

```
aegis-seal/
├── src/
│   └── aegisseal/
│       ├── __init__.py
│       ├── cli.py              # CLI entrypoint
│       ├── scanning/
│       │   ├── engine.py       # Scan orchestration
│       │   ├── detectors.py    # Regex detectors
│       │   ├── entropy.py      # Entropy scanning (opt-in)
│       │   └── baseline.py     # Baseline management
│       ├── fix/
│       │   └── libcst_fix.py   # Auto-fix transformer
│       ├── report/
│       │   ├── sarif.py        # SARIF 2.1.0 generator
│       │   ├── html.py         # HTML report
│       │   └── json_report.py  # JSON report
│       ├── rules/
│       │   └── core.yaml       # Detection rules
│       └── utils/
│           ├── io.py           # File I/O utilities
│           └── ids.py          # Rule ID registry
├── tests/                      # Test suite
├── sample_project/             # Demo project
└── pyproject.toml             # PEP 517/518/621 config
```

## 🤝 Contributing

Contributions are welcome! Please ensure:
- All tests pass (`pytest tests/`)
- Code follows project style (use `ruff`)
- New rules use MIT/Apache licensed patterns only
- Documentation is updated

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Detection patterns derived from:
- [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT)
- [detect-secrets](https://github.com/Yelp/detect-secrets) (Apache 2.0)
- [Secrets-Patterns-DB](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0)

## 🚧 Roadmap

v0.1.0 (MVP) - Current:
- ✅ Regex-based detection
- ✅ Entropy scanning (opt-in)
- ✅ LibCST auto-fix for Python
- ✅ SARIF 2.1.0, JSON, HTML reports
- ✅ Baseline management

Future versions:
- Additional language support for auto-fix (JavaScript, Go, etc.)
- Custom rule definitions
- Integration with secret management tools
- Pre-commit hook support
- Advanced entropy tuning

---

**Made with 🛡️ by the Aegis Seal team**
