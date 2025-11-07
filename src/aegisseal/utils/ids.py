"""Stable rule ID registry and management."""

import hashlib
from typing import Dict

# Reserved ID ranges
# AEGIS-1000 to AEGIS-1999: Core secret detectors
# AEGIS-2000 to AEGIS-2999: Entropy-based detectors
# AEGIS-3000 to AEGIS-3999: Custom/extended detectors

# Registry of known rule IDs
RULE_ID_REGISTRY: Dict[str, int] = {
    # GitHub (1000-1099)
    "github_pat": 1001,
    "github_oauth": 1002,
    "github_app": 1003,
    "github_refresh": 1004,

    # AWS (1100-1199)
    "aws_access_key": 1100,
    "aws_secret_key": 1101,
    "aws_session_token": 1102,

    # Private Keys (1200-1299)
    "generic_private_key": 1200,
    "rsa_private_key": 1201,
    "ssh_private_key": 1202,
    "pgp_private_key": 1203,
    "dsa_private_key": 1204,
    "ec_private_key": 1205,

    # Slack (1300-1399)
    "slack_token": 1300,
    "slack_webhook": 1301,

    # Stripe (1400-1499)
    "stripe_key": 1400,

    # Google/GCP (1500-1599)
    "google_api_key": 1500,
    "google_oauth": 1501,
    "gcp_service_account": 1502,
    "gcp_api_key": 1503,

    # Azure (1600-1699)
    "azure_client_secret": 1600,
    "azure_storage_key": 1601,
    "azure_connection_string": 1602,

    # JWT/Generic (1700-1799)
    "jwt_token": 1700,

    # Generic API (1800-1899)
    "generic_api_key": 1800,

    # Kubernetes (1900-1999)
    "k8s_token": 1900,

    # Entropy-based (2000-2099)
    "entropy_high": 2001,
    "entropy_medium": 2002,

    # GitLab (3000-3099)
    "gitlab_pat": 3000,
    "gitlab_runner_token": 3001,

    # Bitbucket (3100-3199)
    "bitbucket_key": 3100,

    # NPM (3200-3299)
    "npm_token": 3200,

    # PyPI (3300-3399)
    "pypi_token": 3300,

    # Docker (3400-3499)
    "docker_pat": 3400,

    # Twilio (3500-3599)
    "twilio_api_key": 3500,
    "twilio_account_sid": 3501,

    # Discord (3600-3699)
    "discord_webhook": 3600,
    "discord_bot_token": 3601,

    # Auth0 (3700-3799)
    "auth0_client_secret": 3700,

    # OpenAI (3800-3899)
    "openai_api_key": 3800,

    # Heroku (3900-3999)
    "heroku_api_key": 3900,

    # Shopify (4000-4099)
    "shopify_token": 4000,
    "shopify_shared_secret": 4001,

    # SendGrid (4100-4199)
    "sendgrid_api_key": 4100,

    # Mailgun (4200-4299)
    "mailgun_api_key": 4200,

    # Square (4300-4399)
    "square_access_token": 4300,
    "square_oauth_secret": 4301,
}


def get_rule_id(rule_name: str) -> str:
    """
    Get a stable rule ID for a given rule name.

    Args:
        rule_name: The rule name/identifier

    Returns:
        Rule ID in format AEGIS-####
    """
    # Check if we have a registered ID
    if rule_name in RULE_ID_REGISTRY:
        return f"AEGIS-{RULE_ID_REGISTRY[rule_name]:04d}"

    # For unknown rules, use CRC32 fallback (deterministic)
    crc = compute_crc32_id(rule_name)
    # Use 9000+ range for dynamic IDs
    rule_num = 9000 + (crc % 1000)
    return f"AEGIS-{rule_num:04d}"


def compute_crc32_id(text: str) -> int:
    """
    Compute a CRC32-based ID for deterministic fallback.

    Args:
        text: Input text

    Returns:
        CRC32 value as integer
    """
    import zlib

    return zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF


def compute_finding_hash(
    file_path: str, line_number: int, rule_id: str, content: str
) -> str:
    """
    Compute a deterministic hash for a finding (for baseline matching).

    Args:
        file_path: Path to the file
        line_number: Line number of the finding
        rule_id: Rule ID
        content: Content of the line (normalized)

    Returns:
        SHA256 hash (first 16 chars)
    """
    # Normalize content (strip whitespace, lowercase)
    normalized = content.strip().lower()

    # Create hash input
    hash_input = f"{file_path}:{line_number}:{rule_id}:{normalized}"

    # Compute SHA256
    hash_obj = hashlib.sha256(hash_input.encode("utf-8"))
    return hash_obj.hexdigest()[:16]


def compute_line_hash(line_content: str) -> str:
    """
    Compute a stable hash for a line of code.

    Used for SARIF fingerprints to enable deduplication across scans.

    Args:
        line_content: The line content to hash

    Returns:
        SHA-1 hash as hex string (40 chars)
    """
    # Strip whitespace for stability
    normalized = line_content.strip()

    # Compute SHA-1 (SARIF convention)
    hash_obj = hashlib.sha1(normalized.encode("utf-8"))
    return hash_obj.hexdigest()


def stable_sort_results(results: list) -> list:
    """
    Sort results deterministically for byte-identical output.

    Sorts by: (file_path, line_number, rule_id)

    Args:
        results: List of result dictionaries (SARIF or Finding objects)

    Returns:
        Sorted list
    """
    def get_sort_key(result):
        # Handle both Finding objects and dictionaries
        if hasattr(result, 'file_path'):
            # Finding object
            return (result.file_path, result.line_number, result.rule_id)
        elif isinstance(result, dict):
            # SARIF result dictionary
            if 'locations' in result and result['locations']:
                loc = result['locations'][0]
                file_path = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                line_num = loc.get('physicalLocation', {}).get('region', {}).get('startLine', 0)
                rule_id = result.get('ruleId', '')
                return (file_path, line_num, rule_id)
        return ('', 0, '')

    return sorted(results, key=get_sort_key)
