# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7] - 2025-11-07

### Added
- Ship-quality packaging with PEP 621 compliance in `pyproject.toml`
- `MANIFEST.in` for proper package data inclusion
- `--verbose` flag for detailed logging output
- `--list` flag for `rules` command to display table format
- Windows-safe UTF-8 I/O handling for cross-platform compatibility
- Build scripts (`scripts/build_wheel.sh` and `scripts/build_wheel.ps1`)
- Comprehensive `CHANGELOG.md` (this file)
- `CONTRIBUTING.md` with developer setup instructions

### Changed
- Updated `pyproject.toml` with enhanced metadata (keywords, URLs, Python 3.13 support)
- Enhanced `rules` command with table format option (`--list`)
- Improved Twilio API Key pattern to allow uppercase characters (`SK[a-zA-Z0-9]{32}`)
- Improved Twilio Account SID pattern to allow uppercase characters (`AC[a-zA-Z0-9]{32}`)
- Enhanced Kubernetes service account token detection with additional context hints

### Fixed
- Windows compatibility issues with UTF-8 output encoding

## [0.1.6] - 2025-11-06

### Added
- Parallel scanning with `ThreadPoolExecutor` for improved performance
- `--max-workers` flag to control parallelism (default: auto-detected)
- `--max-file-size` flag to skip large files (default: 1MB)
- `--soft-exit` flag to exit with code 0 even when findings are present
- Performance summary output (scan time, files/sec, skipped files)
- Regex pattern caching for faster repeated scans
- `tests/conftest.py` with deterministic random seed (`random.seed(42)`)
- Performance and parallel scanning tests (`tests/test_perf_parallel.py`)

### Changed
- Scan engine refactored for parallel file processing
- File size pre-filtering before scanning to reduce memory usage
- `ScanResult` dataclass now includes `skipped_files` and `scan_time` fields

### Fixed
- GitHub Action pip install path now uses `github.action_path` for external repos

## [0.1.5] - 2025-11-05

### Added
- Pre-commit hook integration (`.pre-commit-hooks.yaml`)
- GitHub Action composite action (`contrib/github-action/action.yml`)
- CLI commands: `hook --install` and `action --example`
- Example GitHub workflow (`.github/workflows/aegis.yml`)
- Adoption & Integration section in README
- 23 new tests for hook and action integration

### Changed
- README updated with pre-commit and GitHub Action usage examples

## [0.1.4] - 2025-11-04

### Added
- Inline suppression support via `# aegis: ignore=RULE-ID` comments
- `Baseline.merge()` method for idempotent baseline updates
- `Baseline.sort_entries()` for deterministic baseline ordering
- `--output` flag for baseline command to specify output path
- `suppression.py` module for inline comment parsing
- 11 new tests for baseline and suppression features

### Changed
- Scan engine now filters findings suppressed by inline comments
- Baseline system enhanced with merge and sort capabilities

## [0.1.3] - 2025-11-03

### Added
- Production-grade SARIF 2.1.0 report generation
- Byte-for-byte deterministic output for all report formats
- SHA-1 hash-based fingerprints in SARIF reports
- Single-file HTML report with embedded SARIF data
- `compute_line_hash()` utility for SARIF fingerprints
- `stable_sort_results()` utility for deterministic ordering

### Changed
- SARIF reports now include `primaryLocationLineHash` fingerprints
- HTML reports no longer include timestamps or UUIDs for determinism
- Rule IDs and results are now sorted deterministically

### Fixed
- SARIF schema compliance issues
- HTML report generation with missing SARIF data argument

## [0.1.2] - 2025-11-02

### Added
- Entropy-based secret detection (opt-in with `--enable-entropy`)
- Baseline management system (`.aegis.baseline`)
- `baseline` command with `--update` flag
- Context-aware detection with allowlist support
- Hash-based baseline matching for content changes

### Changed
- Entropy scanning now requires explicit opt-in via `--enable-entropy` flag

## [0.1.1] - 2025-11-01

### Added
- Initial MVP release
- Regex-based detection for 19+ secret types
- LibCST-based auto-fix for Python files
- SARIF 2.1.0, JSON, and HTML report formats
- CLI commands: `scan`, `fix`, `baseline`, `rules`
- Basic test suite with 39 tests

### Fixed
- Rule ID consistency across all output formats

## [0.1.0] - 2025-10-30

### Added
- Project scaffolding and initial setup
- Core scanning engine
- Basic regex detection rules
- CLI framework with argparse

---

**Legend:**
- `Added` for new features
- `Changed` for changes in existing functionality
- `Deprecated` for soon-to-be removed features
- `Removed` for now removed features
- `Fixed` for bug fixes
- `Security` for vulnerability fixes
