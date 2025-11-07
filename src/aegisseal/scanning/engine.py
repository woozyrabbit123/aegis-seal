"""Main scanning engine with parallel scanning support (Sprint A6)."""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from aegisseal.scanning.baseline import Baseline
from aegisseal.scanning.detectors import DetectorEngine, Finding, load_default_rules
from aegisseal.scanning.entropy import scan_line_entropy
from aegisseal.scanning.suppression import is_suppressed_by_comment
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
    max_workers: int = 0  # 0 = auto (min(32, cpu_count or 4))
    max_file_size: int = 1_000_000  # 1MB default
    include_binaries: bool = False  # Skip binaries by default


@dataclass
class ScanResult:
    """Result of a scan operation."""

    findings: List[Finding]
    scanned_files: int
    total_findings: int
    suppressed_findings: int
    skipped_files: int = 0
    scan_time: float = 0.0


class ScanEngine:
    """Main scanning engine with parallel scanning support."""

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

        # Determine worker count
        if config.max_workers == 0:
            self.max_workers = min(32, os.cpu_count() or 4)
        else:
            self.max_workers = config.max_workers

    def scan(self) -> ScanResult:
        """
        Run the scan with parallel file processing.

        Returns:
            ScanResult with findings and statistics
        """
        start_time = time.time()

        # Collect files to scan
        files_to_scan = []
        skipped_files = 0

        for file_path in walk_files(
            self.config.target_path, self.config.exclude_patterns
        ):
            # Check file size
            try:
                file_size = file_path.stat().st_size
                if file_size > self.config.max_file_size:
                    skipped_files += 1
                    continue
            except OSError:
                skipped_files += 1
                continue

            files_to_scan.append(file_path)

        # Scan files in parallel
        all_findings: List[Finding] = []
        scanned_files = 0
        suppressed_count = 0

        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_file = {
                executor.submit(self._scan_file, file_path): file_path
                for file_path in files_to_scan
            }

            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    findings = future.result()
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

        # Sort findings deterministically for consistent output
        all_findings.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))

        scan_time = time.time() - start_time

        return ScanResult(
            findings=all_findings,
            scanned_files=scanned_files,
            total_findings=len(all_findings),
            suppressed_findings=suppressed_count,
            skipped_files=skipped_files,
            scan_time=scan_time,
        )

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """
        Scan a single file (thread-safe).

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

            # Filter out findings suppressed by inline comments
            line_findings = [
                f for f in line_findings
                if not is_suppressed_by_comment(line, f.rule_id)
            ]

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

                # Filter entropy findings too
                entropy_findings = [
                    f for f in entropy_findings
                    if not is_suppressed_by_comment(line, f.rule_id)
                ]

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
