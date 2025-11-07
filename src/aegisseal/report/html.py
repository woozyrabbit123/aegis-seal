"""HTML report generator (single-file with dark mode)."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from aegisseal import __version__
from aegisseal.scanning.detectors import Finding


def generate_html_report(
    findings: List[Finding],
    scanned_files: int,
    suppressed_count: int = 0,
) -> str:
    """
    Generate a single-file HTML report with dark mode.

    Args:
        findings: List of findings
        scanned_files: Number of files scanned
        suppressed_count: Number of findings suppressed by baseline

    Returns:
        HTML report as string
    """
    # Prepare findings data for JavaScript
    findings_data = []
    for finding in findings:
        findings_data.append(
            {
                "ruleId": finding.rule_id,
                "ruleName": finding.rule_name,
                "severity": finding.severity,
                "file": finding.file_path,
                "line": finding.line_number,
                "redactedMatch": finding.redacted_match,
                "lineContent": finding.line_content.strip(),
            }
        )

    # Count by severity
    severity_counts = {
        "critical": sum(1 for f in findings if f.severity.lower() == "critical"),
        "high": sum(1 for f in findings if f.severity.lower() == "high"),
        "medium": sum(1 for f in findings if f.severity.lower() == "medium"),
        "low": sum(1 for f in findings if f.severity.lower() == "low"),
    }

    report_data = {
        "version": __version__,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "totalFindings": len(findings),
            "scannedFiles": scanned_files,
            "suppressedFindings": suppressed_count,
            "bySeverity": severity_counts,
        },
        "findings": findings_data,
    }

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis Seal Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #3d3d3d;
            --text-primary: #e0e0e0;
            --text-secondary: #b0b0b0;
            --border-color: #444;
            --critical: #ff4444;
            --high: #ff8800;
            --medium: #ffaa00;
            --low: #4488ff;
            --success: #44ff88;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            background: var(--bg-secondary);
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }}

        h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
        }}

        .version {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .summary-card h3 {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 10px;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
        }}

        .severity-critical {{ color: var(--critical); }}
        .severity-high {{ color: var(--high); }}
        .severity-medium {{ color: var(--medium); }}
        .severity-low {{ color: var(--low); }}

        .filters {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }}

        .filter-group {{
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .filter-group label {{
            display: flex;
            align-items: center;
            gap: 5px;
            cursor: pointer;
        }}

        .filter-group input[type="checkbox"] {{
            cursor: pointer;
        }}

        .findings-list {{
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .finding {{
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
        }}

        .finding:last-child {{
            border-bottom: none;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }}

        .finding-title {{
            font-weight: bold;
            font-size: 1.1rem;
        }}

        .severity-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge-critical {{
            background: var(--critical);
            color: white;
        }}

        .badge-high {{
            background: var(--high);
            color: white;
        }}

        .badge-medium {{
            background: var(--medium);
            color: black;
        }}

        .badge-low {{
            background: var(--low);
            color: white;
        }}

        .finding-location {{
            color: var(--text-secondary);
            margin-bottom: 10px;
        }}

        .finding-code {{
            background: var(--bg-tertiary);
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin-top: 10px;
        }}

        .no-findings {{
            padding: 40px;
            text-align: center;
            color: var(--text-secondary);
        }}

        .hidden {{
            display: none !important;
        }}

        footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Aegis Seal Security Report</h1>
            <div class="version">Version {__version__} • Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </header>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value" id="total-findings">{len(findings)}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="value severity-critical">{severity_counts['critical']}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="value severity-high">{severity_counts['high']}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="value severity-medium">{severity_counts['medium']}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="value severity-low">{severity_counts['low']}</div>
            </div>
            <div class="summary-card">
                <h3>Files Scanned</h3>
                <div class="value">{scanned_files}</div>
            </div>
        </div>

        <div class="filters">
            <div class="filter-group">
                <strong>Filter by severity:</strong>
                <label><input type="checkbox" class="severity-filter" value="critical" checked> Critical</label>
                <label><input type="checkbox" class="severity-filter" value="high" checked> High</label>
                <label><input type="checkbox" class="severity-filter" value="medium" checked> Medium</label>
                <label><input type="checkbox" class="severity-filter" value="low" checked> Low</label>
            </div>
        </div>

        <div class="findings-list" id="findings-list">
            <!-- Findings will be rendered here by JavaScript -->
        </div>

        <footer>
            <p>Generated by Aegis Seal v{__version__}</p>
        </footer>
    </div>

    <script>
        window.REPORT_DATA = {json.dumps(report_data)};

        function renderFindings() {{
            const findingsList = document.getElementById('findings-list');
            const checkedSeverities = Array.from(document.querySelectorAll('.severity-filter:checked'))
                .map(cb => cb.value);

            const filteredFindings = window.REPORT_DATA.findings.filter(f =>
                checkedSeverities.includes(f.severity.toLowerCase())
            );

            if (filteredFindings.length === 0) {{
                findingsList.innerHTML = '<div class="no-findings">No findings match the current filters.</div>';
                return;
            }}

            findingsList.innerHTML = filteredFindings.map(finding => `
                <div class="finding" data-severity="${{finding.severity.toLowerCase()}}">
                    <div class="finding-header">
                        <div class="finding-title">${{finding.ruleName}}</div>
                        <span class="severity-badge badge-${{finding.severity.toLowerCase()}}">${{finding.severity}}</span>
                    </div>
                    <div class="finding-location">
                        📄 ${{finding.file}}:${{finding.line}} • 🔍 ${{finding.ruleId}}
                    </div>
                    <div>
                        <strong>Redacted match:</strong> <code>${{finding.redactedMatch}}</code>
                    </div>
                    <div class="finding-code">${{escapeHtml(finding.lineContent)}}</div>
                </div>
            `).join('');
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Initial render
        renderFindings();

        // Add event listeners to filters
        document.querySelectorAll('.severity-filter').forEach(checkbox => {{
            checkbox.addEventListener('change', renderFindings);
        }});
    </script>
</body>
</html>
"""

    return html


def save_html_report(
    html_content: str,
    output_path: Path,
) -> None:
    """
    Save HTML report to file.

    Args:
        html_content: HTML report string
        output_path: Path to save report
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
