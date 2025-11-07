"""Shannon entropy-based secret detection (opt-in only)."""

import math
import re
from typing import List

from aegisseal.scanning.detectors import Finding
from aegisseal.utils.ids import get_rule_id


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Args:
        data: Input string

    Returns:
        Entropy value (bits per character)
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)

    # Count character frequencies
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    # Calculate entropy
    for count in frequencies.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def scan_line_entropy(
    line: str,
    line_number: int,
    file_path: str,
    high_threshold: float = 4.5,
    medium_threshold: float = 4.0,
    min_length: int = 20,
) -> List[Finding]:
    """
    Scan a line for high-entropy strings.

    Args:
        line: The line content
        line_number: Line number (1-indexed)
        file_path: Path to the file
        high_threshold: Entropy threshold for high severity
        medium_threshold: Entropy threshold for medium severity
        min_length: Minimum string length to consider

    Returns:
        List of entropy-based findings
    """
    findings = []

    # Look for potential secrets (quoted strings, tokens, etc.)
    # Match strings in quotes, after = or :, and standalone alphanumeric sequences
    patterns = [
        r'["\']([A-Za-z0-9+/=_-]{20,})["\']',  # Quoted strings
        r'[:=]\s*([A-Za-z0-9+/=_-]{20,})',  # After assignment
        r'\b([A-Za-z0-9+/=_-]{32,})\b',  # Standalone long sequences
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, line)

        for match in matches:
            candidate = match.group(1) if match.lastindex else match.group(0)

            if len(candidate) < min_length:
                continue

            entropy = calculate_shannon_entropy(candidate)

            severity = None
            rule_id = None
            rule_name = None

            if entropy >= high_threshold:
                severity = "high"
                rule_id = get_rule_id("entropy_high")
                rule_name = "High Entropy String"
            elif entropy >= medium_threshold:
                severity = "medium"
                rule_id = get_rule_id("entropy_medium")
                rule_name = "Medium Entropy String"

            if severity:
                # Redact the candidate
                redacted = candidate[:8] + "..." if len(candidate) > 8 else "***"

                finding = Finding(
                    rule_id=rule_id,
                    rule_name=f"{rule_name} (entropy={entropy:.2f})",
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line,
                    matched_string=candidate,
                    severity=severity,
                    redacted_match=redacted,
                )
                findings.append(finding)

    return findings
