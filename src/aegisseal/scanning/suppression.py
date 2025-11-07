"""Inline suppression comment parser for ignoring specific findings."""

import re
from typing import List, Optional, Set


# Pattern: # aegis: ignore=AEGIS-1234 or # aegis:ignore=AEGIS-1234,AEGIS-5678
SUPPRESSION_PATTERN = re.compile(
    r'#\s*aegis:\s*ignore\s*=\s*([\w\-,\s]+)',
    re.IGNORECASE
)


def parse_suppression_comment(line: str) -> Optional[Set[str]]:
    """
    Parse inline suppression comment from a line.

    Supports formats:
    - # aegis: ignore=AEGIS-1234
    - # aegis:ignore=AEGIS-1234
    - # aegis: ignore=AEGIS-1234,AEGIS-5678
    - # AEGIS: IGNORE=AEGIS-1234  (case-insensitive)

    Args:
        line: Line of code to parse

    Returns:
        Set of rule IDs to suppress, or None if no suppression comment found
    """
    match = SUPPRESSION_PATTERN.search(line)
    if not match:
        return None

    # Extract rule IDs (comma-separated)
    rule_ids_str = match.group(1)
    rule_ids = {
        rid.strip().upper()
        for rid in rule_ids_str.split(',')
        if rid.strip()
    }

    return rule_ids if rule_ids else None


def is_suppressed_by_comment(line: str, rule_id: str) -> bool:
    """
    Check if a rule is suppressed by an inline comment on the line.

    Args:
        line: Line of code
        rule_id: Rule ID to check (e.g., "AEGIS-1234")

    Returns:
        True if rule is suppressed by inline comment
    """
    suppressed_rules = parse_suppression_comment(line)
    if suppressed_rules is None:
        return False

    return rule_id.upper() in suppressed_rules
