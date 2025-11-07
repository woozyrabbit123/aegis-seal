"""Stable rule ID registry and management."""

import hashlib
from typing import Dict

# Reserved ID ranges
# AEGIS-1000 to AEGIS-1999: Core secret detectors
# AEGIS-2000 to AEGIS-2999: Entropy-based detectors
# AEGIS-3000 to AEGIS-3999: Custom/extended detectors

# Registry of known rule IDs
RULE_ID_REGISTRY: Dict[str, int] = {
    "github_pat": 1001,
    "github_oauth": 1002,
    "github_app": 1003,
    "github_refresh": 1004,
    "aws_access_key": 1100,
    "aws_secret_key": 1101,
    "aws_session_token": 1102,
    "generic_private_key": 1200,
    "rsa_private_key": 1201,
    "ssh_private_key": 1202,
    "pgp_private_key": 1203,
    "slack_token": 1300,
    "slack_webhook": 1301,
    "stripe_key": 1400,
    "google_api_key": 1500,
    "google_oauth": 1501,
    "azure_client_secret": 1600,
    "jwt_token": 1700,
    "generic_api_key": 1800,
    "entropy_high": 2001,
    "entropy_medium": 2002,
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
