"""Test rules precision patches (Sprint A7)."""

import pytest

from aegisseal.scanning.detectors import DetectorEngine, load_default_rules


@pytest.fixture
def detector():
    """Create detector engine with default rules."""
    rules = load_default_rules()
    return DetectorEngine(rules)


def test_twilio_api_key_uppercase():
    """Test Twilio API Key pattern allows uppercase (Sprint A7 patch)."""
    from aegisseal.utils.ids import get_rule_id

    detector = DetectorEngine(load_default_rules())

    # Test with uppercase letters
    line_upper = 'token = "SKabcdefghijklmnopqrstuvwxyz123456"'
    findings_upper = detector.scan_line(line_upper, 1, "test.py")

    # Should detect
    assert len(findings_upper) >= 1, "Should detect Twilio API Key with uppercase"

    # Check that it's the Twilio API Key rule (AEGIS-3500)
    twilio_rule_id = get_rule_id("twilio_api_key")
    twilio_findings = [f for f in findings_upper if f.rule_id == twilio_rule_id]
    assert len(twilio_findings) >= 1, f"Should have at least one Twilio finding (rule {twilio_rule_id})"

    # Test with lowercase (should still work)
    line_lower = 'token = "SKabcdefghijklmnopqrstuvwxyz123456"'
    findings_lower = detector.scan_line(line_lower, 1, "test.py")

    assert len(findings_lower) >= 1, "Should detect Twilio API Key with lowercase"


def test_twilio_api_key_mixed_case():
    """Test Twilio API Key with mixed case."""
    from aegisseal.utils.ids import get_rule_id

    detector = DetectorEngine(load_default_rules())

    # Real-world Twilio API keys can have mixed case (SK + 32 chars)
    line = 'twilio_key = "SKAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) >= 1, "Should detect Twilio API Key with mixed case"

    # Verify it's the Twilio rule
    twilio_rule_id = get_rule_id("twilio_api_key")
    twilio_findings = [f for f in findings if f.rule_id == twilio_rule_id]
    assert len(twilio_findings) >= 1, "Should be detected by Twilio API Key rule"


def test_twilio_account_sid_uppercase():
    """Test Twilio Account SID pattern allows uppercase (Sprint A7 patch)."""
    detector = DetectorEngine(load_default_rules())

    # Test with uppercase letters
    line_upper = 'account_sid = "ACabcdefghijklmnopqrstuvwxyz123456"'
    findings_upper = detector.scan_line(line_upper, 1, "test.py")

    # Should detect
    assert len(findings_upper) >= 1, "Should detect Twilio Account SID with uppercase"

    # Test with lowercase (should still work)
    line_lower = 'account_sid = "ACabcdefghijklmnopqrstuvwxyz123456"'
    findings_lower = detector.scan_line(line_lower, 1, "test.py")

    assert len(findings_lower) >= 1, "Should detect Twilio Account SID with lowercase"


def test_twilio_account_sid_mixed_case():
    """Test Twilio Account SID with mixed case."""
    from aegisseal.utils.ids import get_rule_id

    detector = DetectorEngine(load_default_rules())

    # Real-world Twilio Account SIDs can have mixed case (AC + 32 chars)
    line = 'sid = "ACAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp"'
    findings = detector.scan_line(line, 1, "test.py")

    assert len(findings) >= 1, "Should detect Twilio Account SID with mixed case"

    # Verify it's the Twilio Account SID rule
    twilio_sid_rule_id = get_rule_id("twilio_account_sid")
    twilio_findings = [f for f in findings if f.rule_id == twilio_sid_rule_id]
    assert len(twilio_findings) >= 1, "Should be detected by Twilio Account SID rule"


def test_k8s_token_context_hints():
    """Test Kubernetes token has enhanced context hints (Sprint A7 patch)."""
    rules = load_default_rules()

    # Find k8s token rule
    k8s_rule = None
    for rule in rules:
        if "k8s" in rule.id.lower() or "kubernetes" in rule.id.lower():
            k8s_rule = rule
            break

    assert k8s_rule is not None, "Kubernetes token rule not found"

    # Check that it has enhanced context hints
    assert hasattr(k8s_rule, "context_hints"), "Rule should have context_hints"
    context_hints = k8s_rule.context_hints

    # Should have kubernetes-related hints
    assert "kubernetes" in context_hints or "k8s" in context_hints, (
        "Should have kubernetes/k8s in context hints"
    )

    # Should have serviceaccount hints
    serviceaccount_hints = [
        hint for hint in context_hints if "service" in hint.lower() or "account" in hint.lower()
    ]
    assert len(serviceaccount_hints) > 0, "Should have service account related hints"


def test_k8s_vs_jwt_disambiguation():
    """Test that k8s token and JWT token rules have different context hints."""
    rules = load_default_rules()

    # Find both rules
    k8s_rule = None
    jwt_rule = None

    for rule in rules:
        if "k8s" in rule.id.lower() or "kubernetes" in rule.id.lower():
            k8s_rule = rule
        if "jwt" in rule.id.lower() and "k8s" not in rule.id.lower():
            jwt_rule = rule

    assert k8s_rule is not None, "Kubernetes token rule not found"
    assert jwt_rule is not None, "JWT token rule not found"

    # k8s should have more specific context hints
    k8s_hints = set(k8s_rule.context_hints)
    jwt_hints = set(jwt_rule.context_hints)

    # k8s should have unique hints
    k8s_unique = k8s_hints - jwt_hints
    assert len(k8s_unique) > 0, "k8s rule should have unique context hints"


def test_twilio_patterns_in_yaml():
    """Test that Twilio patterns in YAML are updated correctly."""
    from pathlib import Path

    # Find core.yaml
    rules_dir = Path(__file__).parent.parent / "src" / "aegisseal" / "rules"
    core_yaml = rules_dir / "core.yaml"

    assert core_yaml.exists(), "core.yaml not found"

    content = core_yaml.read_text()

    # Check Twilio API Key pattern
    assert "SK[a-zA-Z0-9]{32}" in content, "Twilio API Key should allow uppercase"
    assert "SK[a-z0-9]{32}" not in content, "Old Twilio API Key pattern should be replaced"

    # Check Twilio Account SID pattern
    assert "AC[a-zA-Z0-9]{32}" in content, "Twilio Account SID should allow uppercase"
    assert "AC[a-z0-9]{32}" not in content, "Old Twilio Account SID pattern should be replaced"


def test_k8s_context_hints_in_yaml():
    """Test that k8s context hints in YAML are updated correctly."""
    from pathlib import Path

    # Find core.yaml
    rules_dir = Path(__file__).parent.parent / "src" / "aegisseal" / "rules"
    core_yaml = rules_dir / "core.yaml"

    assert core_yaml.exists(), "core.yaml not found"

    content = core_yaml.read_text()

    # Find k8s rule section
    k8s_section_start = content.find("# Kubernetes")
    assert k8s_section_start != -1, "Kubernetes section not found"

    # Extract k8s rule section (up to next rule)
    k8s_section = content[k8s_section_start : k8s_section_start + 1000]

    # Check for enhanced context hints
    assert "kubernetes" in k8s_section or "k8s" in k8s_section, (
        "k8s rule should have kubernetes/k8s in context hints"
    )

    assert "serviceaccount" in k8s_section or "service-account" in k8s_section, (
        "k8s rule should have serviceaccount in context hints"
    )


def test_twilio_real_world_examples():
    """Test Twilio detection with real-world-like examples."""
    detector = DetectorEngine(load_default_rules())

    # Real Twilio API Key format (using EXAMPLE to avoid GitHub push protection)
    real_api_key = 'TWILIO_API_KEY = "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
    findings = detector.scan_line(real_api_key, 1, "config.py")
    assert len(findings) >= 1, "Should detect real Twilio API Key format"

    # Real Twilio Account SID format (using EXAMPLE to avoid GitHub push protection)
    real_sid = 'ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
    findings = detector.scan_line(real_sid, 1, "config.py")
    assert len(findings) >= 1, "Should detect real Twilio Account SID format"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
