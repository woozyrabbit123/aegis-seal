"""Main scanning engine that orchestrates the detection process."""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from aegisseal.scanning.baseline import Baseline
from aegisseal.scanning.detectors import DetectorEngine, Finding, load_default_rules
from aegisseal.scanning.entropy import scan_line_entropy
from aegisseal.utils.io import read_file_lines, walk_files


@dataclass
class ScanConfig:
    """Configuration for scanning."""

    target_path: Path
    exclude_patterns: List[str] | None = None
    enable_entropy: bool = False
    baseline_path: Path | None = None
    entropy_high_threshold: float = 4.5
    entropy_medium_threshold: float = 4.0


@dataclass
class ScanResult:
    """Result of a scan operation."""

    findings: List[Finding]
    scanned_files: int
    total_findings: int
    suppressed_findings: int


class ScanEngine:
    """Main scanning engine."""

    def __init__(self, config: ScanConfig):
        """
        Initialize scan engine.

        Args:
            config: Scan configuration
        """
        self.config = config
        self.rules = load_default_rules()
        self.detector = DetectorEngine(self.rules)
        self.baseline: Optional[Baseline] = None

        # Load baseline if specified
        if config.baseline_path and config.baseline_path.exists():
            self.baseline = Baseline.load(config.baseline_path)

    def scan(self) -> ScanResult:
        """
        Run the scan.

        Returns:
            ScanResult with findings and statistics
        """
        all_findings: List[Finding] = []
        scanned_files = 0
        suppressed_count = 0

        # Walk files
        for file_path in walk_files(
            self.config.target_path, self.config.exclude_patterns
        ):
            try:
                findings = self._scan_file(file_path)
                scanned_files += 1

                # Apply baseline filtering
                if self.baseline:
                    original_count = len(findings)
                    findings = self.baseline.filter_findings(findings)
                    suppressed_count += original_count - len(findings)

                all_findings.extend(findings)

            except Exception as e:
                # Log error but continue scanning
                print(f"Warning: Failed to scan {file_path}: {e}")
                continue

        # Sort findings by file path and line number for deterministic output
        all_findings.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))

        return ScanResult(
            findings=all_findings,
            scanned_files=scanned_files,
            total_findings=len(all_findings),
            suppressed_findings=suppressed_count,
        )

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """
        Scan a single file.

        Args:
            file_path: Path to file

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        try:
            lines = read_file_lines(file_path)
        except Exception as e:
            raise IOError(f"Failed to read {file_path}: {e}")

        # Convert to relative path for reporting
        try:
            relative_path = str(
                file_path.relative_to(self.config.target_path.resolve())
            )
        except ValueError:
            relative_path = str(file_path)

        # Scan each line
        for line_number, line in enumerate(lines, start=1):
            # Regex-based detection
            line_findings = self.detector.scan_line(line, line_number, relative_path)
            findings.extend(line_findings)

            # Entropy-based detection (opt-in)
            if self.config.enable_entropy:
                entropy_findings = scan_line_entropy(
                    line,
                    line_number,
                    relative_path,
                    high_threshold=self.config.entropy_high_threshold,
                    medium_threshold=self.config.entropy_medium_threshold,
                )
                findings.extend(entropy_findings)

        return findings

    def get_rules(self) -> List[dict]:
        """
        Get list of active rules.

        Returns:
            List of rule information
        """
        from aegisseal.utils.ids import get_rule_id

        return [
            {
                "id": get_rule_id(rule.id),
                "name": rule.name,
                "severity": rule.severity,
                "description": rule.description,
            }
            for rule in self.rules
        ]
