"""Command-line interface for Aegis Seal."""

import argparse
import sys
from pathlib import Path

# Windows-safe UTF-8 I/O handling
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass  # Silently fail if reconfigure not available

from aegisseal import __version__
from aegisseal.fix.libcst_fix import apply_fixes, filter_python_findings
from aegisseal.report.html import generate_html_report, save_html_report
from aegisseal.report.json_report import generate_json_report, save_json_report
from aegisseal.report.sarif import generate_sarif_report, save_sarif_report
from aegisseal.scanning.baseline import Baseline
from aegisseal.scanning.engine import ScanConfig, ScanEngine


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    target_path = Path(args.target).resolve()

    if not target_path.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        return 1

    # Prepare configuration
    exclude_patterns = args.exclude.split(",") if args.exclude else None
    baseline_path = Path(args.baseline) if args.baseline else target_path / ".aegis.baseline"

    config = ScanConfig(
        target_path=target_path,
        exclude_patterns=exclude_patterns,
        enable_entropy=args.enable_entropy,
        baseline_path=baseline_path if baseline_path.exists() else None,
    )

    # Run scan
    print(f"🔍 Scanning {target_path}...")
    if args.enable_entropy:
        print("⚡ Entropy scanning enabled")

    engine = ScanEngine(config)
    result = engine.scan()

    print(f"✅ Scanned {result.scanned_files} files")
    print(f"🔎 Found {result.total_findings} potential secrets")

    if result.suppressed_findings > 0:
        print(f"🔇 Suppressed {result.suppressed_findings} findings (baseline)")

    # Generate reports
    output_dir = Path(args.output) if args.output else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    formats = args.format.split(",") if args.format != "all" else ["json", "sarif", "html"]

    for fmt in formats:
        fmt = fmt.strip().lower()

        if fmt == "json":
            json_data = generate_json_report(
                result.findings, result.scanned_files, result.suppressed_findings
            )
            json_path = output_dir / "scan.json"
            save_json_report(json_data, json_path)
            print(f"📄 JSON report saved to {json_path}")

        elif fmt == "sarif":
            sarif_data = generate_sarif_report(result.findings, engine.rules, target_path)
            sarif_path = output_dir / "scan.sarif"
            save_sarif_report(sarif_data, sarif_path)
            print(f"📄 SARIF report saved to {sarif_path}")

        elif fmt == "html":
            html_content = generate_html_report(
                result.findings, result.scanned_files, result.suppressed_findings
            )
            html_path = output_dir / "scan.html"
            save_html_report(html_content, html_path)
            print(f"📄 HTML report saved to {html_path}")

    # Return exit code based on findings
    if result.total_findings > 0:
        print(f"\n⚠️  Found {result.total_findings} potential secrets!")
        return 1

    print("\n✅ No secrets found!")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """Execute the fix command."""
    target_path = Path(args.target).resolve()

    if not target_path.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        return 1

    # Run a scan first to find secrets
    config = ScanConfig(
        target_path=target_path,
        enable_entropy=False,  # Don't use entropy for fixes
    )

    print(f"🔍 Scanning {target_path} for fixable secrets...")
    engine = ScanEngine(config)
    result = engine.scan()

    # Filter for Python files only
    python_findings = filter_python_findings(result.findings)

    if not python_findings:
        print("✅ No fixable secrets found in Python files")
        return 0

    # Filter by rule if specified
    if args.rule:
        python_findings = [f for f in python_findings if f.rule_id == args.rule]
        if not python_findings:
            print(f"No findings for rule {args.rule}")
            return 0

    # Group findings by file
    findings_by_file = {}
    for finding in python_findings:
        file_path = target_path / finding.file_path
        if file_path not in findings_by_file:
            findings_by_file[file_path] = []
        findings_by_file[file_path].append(finding)

    print(f"🔧 Found {len(python_findings)} fixable secret(s) in {len(findings_by_file)} file(s)")

    dry_run = not args.yes

    if dry_run:
        print("\n🔍 DRY RUN MODE (use --yes to apply changes)\n")

    # Apply fixes
    total_fixed = 0
    for file_path, findings in findings_by_file.items():
        print(f"\n📝 Processing {file_path.relative_to(target_path)}...")

        success, output = apply_fixes(file_path, findings, dry_run=dry_run)

        if success:
            if dry_run and output and output.strip():
                print(output)
            elif not dry_run:
                print(f"✅ {output}")
            total_fixed += len(findings)
        else:
            print(f"❌ Error: {output}", file=sys.stderr)

    if dry_run:
        print(f"\n💡 To apply these fixes, run with --yes flag")
        return 0
    else:
        print(f"\n✅ Fixed {total_fixed} secret(s)")
        return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    """Execute the baseline command."""
    target_path = Path(args.target).resolve()

    if not target_path.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        return 1

    baseline_path = target_path / ".aegis.baseline"

    if args.update:
        # Run scan to find all secrets
        config = ScanConfig(
            target_path=target_path,
            enable_entropy=False,  # Don't include entropy in baseline
        )

        print(f"🔍 Scanning {target_path} to update baseline...")
        engine = ScanEngine(config)
        result = engine.scan()

        # Create baseline from findings
        baseline = Baseline()
        for finding in result.findings:
            baseline.add_finding(finding)

        # Save baseline
        baseline.save(baseline_path)
        print(f"✅ Baseline updated with {len(result.findings)} finding(s)")
        print(f"📄 Saved to {baseline_path}")
        return 0

    else:
        # Show baseline info
        if not baseline_path.exists():
            print(f"No baseline found at {baseline_path}")
            return 1

        baseline = Baseline.load(baseline_path)
        print(f"📄 Baseline: {baseline_path}")
        print(f"📊 Contains {len(baseline.entries)} finding(s)")
        return 0


def cmd_rules(args: argparse.Namespace) -> int:
    """Execute the rules command."""
    from aegisseal.scanning.detectors import load_default_rules
    from aegisseal.utils.ids import get_rule_id

    rules = load_default_rules()

    if args.list:
        # Table format
        print(f"📋 Active Detection Rules ({len(rules)} total)\n")

        # Calculate column widths
        max_id_len = max(len(get_rule_id(r.id)) for r in rules)
        max_name_len = max(len(r.name) for r in rules)
        max_severity_len = max(len(r.severity) for r in rules)

        # Print header
        header = f"{'Rule ID':<{max_id_len}}  {'Name':<{max_name_len}}  {'Severity':<{max_severity_len}}"
        print(header)
        print("=" * len(header))

        # Print rows
        for rule in rules:
            rule_id = get_rule_id(rule.id)
            print(f"{rule_id:<{max_id_len}}  {rule.name:<{max_name_len}}  {rule.severity.upper():<{max_severity_len}}")

        print()
        return 0
    else:
        # Detailed format (default)
        print(f"📋 Active Detection Rules ({len(rules)} total)\n")

        for rule in rules:
            rule_id = get_rule_id(rule.id)
            print(f"  {rule_id} - {rule.name}")
            print(f"    Severity: {rule.severity.upper()}")
            print(f"    Description: {rule.description}")
            print()

        return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="aegis-seal",
        description="Aegis Seal - Local-first secret scanner with auto-fix",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for secrets")
    scan_parser.add_argument("--target", required=True, help="Path to scan")
    scan_parser.add_argument(
        "--enable-entropy", action="store_true", help="Enable entropy-based detection"
    )
    scan_parser.add_argument(
        "--exclude", help="Comma-separated list of additional patterns to exclude"
    )
    scan_parser.add_argument(
        "--format",
        default="all",
        help="Output format: json, sarif, html, or all (default: all)",
    )
    scan_parser.add_argument(
        "--output", default="reports", help="Output directory for reports (default: reports)"
    )
    scan_parser.add_argument("--baseline", help="Path to baseline file (default: .aegis.baseline)")

    # Fix command
    fix_parser = subparsers.add_parser("fix", help="Auto-fix secrets in Python files")
    fix_parser.add_argument("--target", required=True, help="Path to fix")
    fix_parser.add_argument("--rule", help="Only fix findings for specific rule ID")
    fix_parser.add_argument(
        "--yes", action="store_true", help="Apply fixes (default: dry-run)"
    )

    # Baseline command
    baseline_parser = subparsers.add_parser("baseline", help="Manage baseline")
    baseline_parser.add_argument("--target", required=True, help="Path to scan")
    baseline_parser.add_argument(
        "--update", action="store_true", help="Update baseline with current findings"
    )

    # Rules command
    rules_parser = subparsers.add_parser("rules", help="List active detection rules")
    rules_parser.add_argument("--list", action="store_true", help="Show rules in table format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "scan":
            return cmd_scan(args)
        elif args.command == "fix":
            return cmd_fix(args)
        elif args.command == "baseline":
            return cmd_baseline(args)
        elif args.command == "rules":
            return cmd_rules(args)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
