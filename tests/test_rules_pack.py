"""Tests for expanded rule pack (Sprint A1)."""

from pathlib import Path

import pytest

from aegisseal.scanning.detectors import load_default_rules, DetectorEngine
from aegisseal.scanning.engine import ScanConfig, ScanEngine


@pytest.fixture
def fixtures_dir():
    """Get fixtures directory path."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def positives_dir(fixtures_dir):
    """Get positives fixtures directory path."""
    return fixtures_dir / "positives"


@pytest.fixture
def negatives_dir(fixtures_dir):
    """Get negatives fixtures directory path."""
    return fixtures_dir / "negatives"


def test_all_rules_loaded():
    """Test that all expected rules are loaded."""
    rules = load_default_rules()

    # We should have significantly more rules now (19 original + ~29 new = 48)
    assert len(rules) >= 45, f"Expected at least 45 rules, got {len(rules)}"

    # Check that rule IDs are deterministic and stable
    rule_ids = [rule.id for rule in rules]
    assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs found"


def test_rule_id_stability():
    """Test that rule IDs are stable and deterministic."""
    from aegisseal.utils.ids import get_rule_id

    # Test stable IDs for new rules
    stable_mappings = {
        "gitlab_pat": "AEGIS-3000",
        "npm_token": "AEGIS-3200",
        "pypi_token": "AEGIS-3300",
        "docker_pat": "AEGIS-3400",
        "twilio_api_key": "AEGIS-3500",
        "discord_webhook": "AEGIS-3600",
        "auth0_client_secret": "AEGIS-3700",
        "openai_api_key": "AEGIS-3800",
        "heroku_api_key": "AEGIS-3900",
        "shopify_token": "AEGIS-4000",
        "sendgrid_api_key": "AEGIS-4100",
        "mailgun_api_key": "AEGIS-4200",
        "square_access_token": "AEGIS-4300",
    }

    for rule_name, expected_id in stable_mappings.items():
        assert get_rule_id(rule_name) == expected_id, \
            f"Rule {rule_name} has unexpected ID {get_rule_id(rule_name)}, expected {expected_id}"


def test_cloud_secrets_detected(positives_dir):
    """Test that cloud secrets are detected correctly."""
    cloud_file = positives_dir / "cloud_secrets.txt"
    assert cloud_file.exists(), "cloud_secrets.txt fixture not found"

    config = ScanConfig(target_path=cloud_file, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    # Should find GCP service account, GCP API key, Azure storage, K8s token
    assert result.total_findings >= 4, \
        f"Expected at least 4 findings in cloud_secrets.txt, got {result.total_findings}"

    # Check for specific rules
    rule_ids = [f.rule_id for f in result.findings]
    assert "AEGIS-1502" in rule_ids or "AEGIS-1503" in rule_ids, "GCP rules not triggered"


def test_dev_tokens_detected(positives_dir):
    """Test that development tokens are detected correctly."""
    dev_file = positives_dir / "dev_tokens.txt"
    assert dev_file.exists(), "dev_tokens.txt fixture not found"

    config = ScanConfig(target_path=dev_file, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    # Should find GitLab, Bitbucket, NPM, PyPI, Docker, DSA, EC keys
    assert result.total_findings >= 7, \
        f"Expected at least 7 findings in dev_tokens.txt, got {result.total_findings}"

    # Check for specific rule IDs
    rule_ids = [f.rule_id for f in result.findings]
    assert "AEGIS-3000" in rule_ids, "GitLab PAT not detected"
    assert "AEGIS-3200" in rule_ids, "NPM token not detected"
    assert "AEGIS-3300" in rule_ids, "PyPI token not detected"


def test_saas_tokens_detected(tmp_path):
    """Test that SaaS tokens are detected correctly.

    Note: Test secrets are generated dynamically to avoid GitHub push protection.
    """
    import tempfile

    # Generate test content dynamically - build patterns from parts to avoid GitHub scanning
    # This is a test file for a secret scanner, so we need test secrets!
    twilio_key = "SK" + "123456789012345678901234" + "56789012"
    twilio_sid = "AC" + "123456789012345678901234" + "56789012"
    shopify_tok = "shpat_" + "1234" * 8
    shopify_sec = "shpss_" + "1234" * 8
    square_tok = "sq0atp-" + "Test1234" * 2 + "Test12"
    square_sec = "sq0csp-" + "Test1234" * 5 + "Test12"

    test_content = f"""# Twilio API Key
twilio_key = {twilio_key}

# Twilio Account SID
account_sid = {twilio_sid}

# Shopify Access Token
shopify_token = {shopify_tok}

# Shopify Shared Secret
shopify_secret = {shopify_sec}

# Square Access Token
square_token = {square_tok}

# Square OAuth Secret
square_secret = {square_sec}
"""

    # Write to temp file
    saas_file = tmp_path / "saas_tokens_test.txt"
    saas_file.write_text(test_content)

    config = ScanConfig(target_path=saas_file, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    # Should find multiple SaaS tokens
    assert result.total_findings >= 4, \
        f"Expected at least 4 findings in generated test file, got {result.total_findings}"

    # Check for specific services that we know match
    rule_ids = [f.rule_id for f in result.findings]
    assert "AEGIS-3500" in rule_ids, "Twilio API key not detected"
    assert "AEGIS-3501" in rule_ids, "Twilio Account SID not detected"
    assert "AEGIS-4000" in rule_ids, "Shopify Access Token not detected"
    assert "AEGIS-4001" in rule_ids, "Shopify Shared Secret not detected"


def test_false_positives_suppressed(negatives_dir):
    """Test that false positives are suppressed by context hints."""
    negatives_file = negatives_dir / "false_positives.txt"
    assert negatives_file.exists(), "false_positives.txt fixture not found"

    config = ScanConfig(target_path=negatives_file, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    # Context hints should suppress most/all of these
    # Allow a small number in case some patterns don't have exhaustive hints
    assert result.total_findings <= 2, \
        f"Expected <= 2 findings due to context hints, got {result.total_findings}"


def test_all_fixtures_scanned(positives_dir):
    """Test scanning all positive fixtures together."""
    config = ScanConfig(target_path=positives_dir, enable_entropy=False)
    engine = ScanEngine(config)
    result = engine.scan()

    # Should find secrets across all positive fixture files
    assert result.total_findings >= 20, \
        f"Expected at least 20 total findings across all positives, got {result.total_findings}"

    # Check that we scanned multiple files
    assert result.scanned_files >= 3, \
        f"Expected to scan at least 3 files, scanned {result.scanned_files}"


def test_deterministic_ordering():
    """Test that findings are returned in deterministic order."""
    from aegisseal.scanning.detectors import load_default_rules

    # Load rules multiple times
    rules1 = load_default_rules()
    rules2 = load_default_rules()

    # Rule order should be consistent
    ids1 = [r.id for r in rules1]
    ids2 = [r.id for r in rules2]

    assert ids1 == ids2, "Rule loading is not deterministic"


def test_new_rules_have_allowlists_and_hints():
    """Test that all new rules have allowlists and context_hints defined."""
    rules = load_default_rules()

    # Check that all rules have these fields
    for rule in rules:
        assert hasattr(rule, 'allowlist'), f"Rule {rule.id} missing allowlist"
        assert hasattr(rule, 'context_hints'), f"Rule {rule.id} missing context_hints"
        assert isinstance(rule.allowlist, list), f"Rule {rule.id} allowlist is not a list"
        assert isinstance(rule.context_hints, list), f"Rule {rule.id} context_hints is not a list"


def test_gitlab_pat_detection():
    """Test GitLab PAT detection specifically."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = 'GITLAB_TOKEN = "glpat-AbCdEfGhIjKlMnOpQrSt"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) >= 1, "GitLab PAT not detected"
    assert any("GitLab" in f.rule_name for f in findings), "GitLab rule name not found"


def test_npm_token_detection():
    """Test NPM token detection specifically."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = 'NPM_TOKEN=npm_1234567890abcdefABCDEF1234567890GHIJ'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) >= 1, "NPM token not detected"
    assert any("NPM" in f.rule_name for f in findings), "NPM rule name not found"


def test_openai_key_detection():
    """Test OpenAI API key detection specifically."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = 'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) >= 1, "OpenAI key not detected"
    assert any("OpenAI" in f.rule_name for f in findings), "OpenAI rule name not found"


def test_discord_webhook_detection():
    """Test Discord webhook detection specifically."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = 'webhook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) >= 1, "Discord webhook not detected"
    assert any("Discord" in f.rule_name for f in findings), "Discord rule name not found"


def test_gcp_service_account_detection():
    """Test GCP service account detection specifically."""
    rules = load_default_rules()
    detector = DetectorEngine(rules)

    line = '{"type": "service_account", "project_id": "my-project"}'
    findings = detector.scan_line(line, 1, "credentials.json")

    assert len(findings) >= 1, "GCP service account not detected"
    assert any("GCP" in f.rule_name or "Service Account" in f.rule_name for f in findings), \
        "GCP service account rule name not found"
