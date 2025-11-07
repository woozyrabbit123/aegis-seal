"""Baseline management for suppressing known findings."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

from aegisseal.scanning.detectors import Finding
from aegisseal.utils.ids import compute_finding_hash


@dataclass
class BaselineEntry:
    """Represents a baseline entry."""

    file_path: str
    line_number: int
    rule_id: str
    finding_hash: str


class Baseline:
    """Manages baseline of known/approved findings."""

    def __init__(self, entries: List[BaselineEntry] | None = None):
        """Initialize baseline."""
        self.entries = entries or []
        self._hashes: Set[str] = {entry.finding_hash for entry in self.entries}

    def is_suppressed(self, finding: Finding) -> bool:
        """
        Check if a finding is suppressed by the baseline.

        Args:
            finding: The finding to check

        Returns:
            True if finding is in baseline
        """
        finding_hash = compute_finding_hash(
            finding.file_path,
            finding.line_number,
            finding.rule_id,
            finding.line_content,
        )
        return finding_hash in self._hashes

    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the baseline.

        Args:
            finding: The finding to add
        """
        finding_hash = compute_finding_hash(
            finding.file_path,
            finding.line_number,
            finding.rule_id,
            finding.line_content,
        )

        if finding_hash not in self._hashes:
            entry = BaselineEntry(
                file_path=finding.file_path,
                line_number=finding.line_number,
                rule_id=finding.rule_id,
                finding_hash=finding_hash,
            )
            self.entries.append(entry)
            self._hashes.add(finding_hash)

    def merge(self, findings: List[Finding]) -> None:
        """
        Merge new findings into the baseline (preserving existing entries).

        Args:
            findings: List of findings to merge
        """
        for finding in findings:
            self.add_finding(finding)

    def sort_entries(self) -> None:
        """Sort entries deterministically by (file, line, rule) for idempotent output."""
        self.entries.sort(key=lambda e: (e.file_path, e.line_number, e.rule_id))

    def save(self, baseline_path: Path) -> None:
        """
        Save baseline to file with deterministic ordering.

        Args:
            baseline_path: Path to baseline file
        """
        # Sort entries before saving for deterministic output
        self.sort_entries()

        data = {
            "version": "1.0",
            "entries": [
                {
                    "file": entry.file_path,
                    "line": entry.line_number,
                    "rule": entry.rule_id,
                    "hash": entry.finding_hash,
                }
                for entry in self.entries
            ],
        }

        # Ensure parent directory exists
        baseline_path.parent.mkdir(parents=True, exist_ok=True)

        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

    @classmethod
    def load(cls, baseline_path: Path) -> "Baseline":
        """
        Load baseline from file.

        Args:
            baseline_path: Path to baseline file

        Returns:
            Baseline object
        """
        if not baseline_path.exists():
            return cls()

        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            entries = [
                BaselineEntry(
                    file_path=entry["file"],
                    line_number=entry["line"],
                    rule_id=entry["rule"],
                    finding_hash=entry["hash"],
                )
                for entry in data.get("entries", [])
            ]

            return cls(entries)
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid baseline file: {e}")

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Filter out findings that are in the baseline.

        Args:
            findings: List of findings

        Returns:
            List of findings not in baseline
        """
        return [f for f in findings if not self.is_suppressed(f)]
