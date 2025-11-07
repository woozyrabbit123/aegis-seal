"""Tests for opt-in entropy scanning."""

import pytest
from pathlib import Path
import tempfile

from aegisseal.scanning.entropy import calculate_shannon_entropy, scan_line_entropy
from aegisseal.scanning.engine import ScanConfig, ScanEngine


def test_shannon_entropy_calculation():
    """Test Shannon entropy calculation."""
    # Low entropy (repeated characters)
    low_entropy = "aaaaaaaaaaaaaaaa"
    assert calculate_shannon_entropy(low_entropy) < 2.0

    # High entropy (random-looking)
    high_entropy = "aB3$xK9#mP2@qR7&"
    assert calculate_shannon_entropy(high_entropy) > 3.0

    # Very high entropy (base64-like)
    very_high = "J8fK3mN9pQ2rT5vX7wZ4aB6cD8eF0gH1"
    assert calculate_shannon_entropy(very_high) > 4.0


def test_entropy_disabled_by_default():
    """Test that entropy scanning is disabled by default."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create a test file with high-entropy string
        test_file = tmpdir / "test.py"
        test_file.write_text('secret = "aB3xK9mP2qR7wZ4aB6cD8eF0gH1jK3mN9pQ2rT5vX7"')

        # Scan without entropy
        config = ScanConfig(
            target_path=tmpdir,
            enable_entropy=False,
        )

        engine = ScanEngine(config)
        result = engine.scan()

        # Should not detect entropy-based findings
        entropy_findings = [f for f in result.findings if "Entropy" in f.rule_name]
        assert len(entropy_findings) == 0


def test_entropy_enabled_with_flag():
    """Test that entropy scanning works when enabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create a test file with high-entropy string
        test_file = tmpdir / "test.py"
        test_file.write_text('secret = "aB3xK9mP2qR7wZ4aB6cD8eF0gH1jK3mN9pQ2rT5vX7wZ4aB6cD8"')

        # Scan with entropy enabled
        config = ScanConfig(
            target_path=tmpdir,
            enable_entropy=True,
        )

        engine = ScanEngine(config)
        result = engine.scan()

        # Should detect entropy-based findings
        entropy_findings = [f for f in result.findings if "Entropy" in f.rule_name]
        assert len(entropy_findings) > 0


def test_entropy_line_scanning():
    """Test entropy-based line scanning."""
    line = 'api_key = "aB3xK9mP2qR7wZ4aB6cD8eF0gH1jK3mN9pQ2rT5vX7"'
    findings = scan_line_entropy(line, 1, "test.py", high_threshold=4.5)

    # Should find high-entropy string
    assert len(findings) > 0
    assert "Entropy" in findings[0].rule_name


def test_entropy_min_length():
    """Test that entropy only triggers on sufficiently long strings."""
    # Short high-entropy string
    short_line = 'x = "aB3xK9"'
    findings = scan_line_entropy(short_line, 1, "test.py", min_length=20)

    # Should not trigger (too short)
    assert len(findings) == 0

    # Long high-entropy string
    long_line = 'x = "aB3xK9mP2qR7wZ4aB6cD8eF0gH1"'
    findings = scan_line_entropy(long_line, 1, "test.py", min_length=20)

    # Should trigger
    assert len(findings) > 0
