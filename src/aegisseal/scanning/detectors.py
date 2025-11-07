"""Regex-based secret detectors."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from aegisseal.utils.ids import get_rule_id


@dataclass
class Rule:
    """Represents a detection rule."""

    id: str
    name: str
    pattern: str
    severity: str
    context_hints: List[str]
    allowlist: List[str]
    description: str
    compiled_pattern: re.Pattern
    compiled_allowlist: List[re.Pattern]


@dataclass
class Finding:
    """Represents a detected secret."""

    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    line_content: str
    matched_string: str
    severity: str
    redacted_match: str


class DetectorEngine:
    """Regex-based detector engine."""

    def __init__(self, rules: List[Rule]):
        """Initialize detector with rules."""
        self.rules = rules

    def scan_line(
        self,
        line: str,
        line_number: int,
        file_path: str,
    ) -> List[Finding]:
        """
        Scan a single line for secrets.

        Args:
            line: The line content
            line_number: Line number (1-indexed)
            file_path: Path to the file

        Returns:
            List of findings
        """
        findings = []

        for rule in self.rules:
            matches = rule.compiled_pattern.finditer(line)

            for match in matches:
                matched_string = match.group(0)

                # Check allowlist
                if self._is_allowlisted(matched_string, rule):
                    continue

                # Check context hints (suppress if found)
                if self._has_context_hint(line.lower(), rule.context_hints):
                    continue

                # Redact the matched string
                redacted = self._redact_match(matched_string)

                finding = Finding(
                    rule_id=get_rule_id(rule.id),
                    rule_name=rule.name,
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line,
                    matched_string=matched_string,
                    severity=rule.severity,
                    redacted_match=redacted,
                )
                findings.append(finding)

        return findings

    @staticmethod
    def _is_allowlisted(matched_string: str, rule: Rule) -> bool:
        """Check if a match is in the allowlist."""
        for allowlist_pattern in rule.compiled_allowlist:
            if allowlist_pattern.search(matched_string):
                return True
        return False

    @staticmethod
    def _has_context_hint(line_lower: str, context_hints: List[str]) -> bool:
        """Check if line contains context hints suggesting false positive."""
        for hint in context_hints:
            if hint in line_lower:
                return True
        return False

    @staticmethod
    def _redact_match(matched_string: str, max_show: int = 8) -> str:
        """Redact a matched secret."""
        if len(matched_string) <= max_show:
            return "***"
        return f"{matched_string[:max_show]}..."


def load_rules_from_yaml(yaml_path: Path) -> List[Rule]:
    """
    Load detection rules from YAML file.

    Args:
        yaml_path: Path to YAML rules file

    Returns:
        List of compiled Rule objects
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = []
    for rule_data in data.get("rules", []):
        # Compile the main pattern
        pattern = rule_data["pattern"]
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern in rule {rule_data['id']}: {e}")

        # Compile allowlist patterns
        compiled_allowlist = []
        for allowlist_item in rule_data.get("allowlist", []):
            # Escape literal strings or compile as regex
            try:
                compiled_allowlist.append(re.compile(re.escape(allowlist_item)))
            except re.error:
                pass

        rule = Rule(
            id=rule_data["id"],
            name=rule_data["name"],
            pattern=pattern,
            severity=rule_data.get("severity", "medium"),
            context_hints=rule_data.get("context_hints", []),
            allowlist=rule_data.get("allowlist", []),
            description=rule_data.get("description", ""),
            compiled_pattern=compiled_pattern,
            compiled_allowlist=compiled_allowlist,
        )
        rules.append(rule)

    return rules


def load_default_rules() -> List[Rule]:
    """Load default core rules bundled with the package."""
    # Find the rules directory relative to this file
    rules_dir = Path(__file__).parent.parent / "rules"
    core_rules_path = rules_dir / "core.yaml"

    if not core_rules_path.exists():
        raise FileNotFoundError(f"Default rules not found at {core_rules_path}")

    return load_rules_from_yaml(core_rules_path)
