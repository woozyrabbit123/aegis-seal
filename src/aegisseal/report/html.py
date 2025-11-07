"""HTML report generator with embedded SARIF data (deterministic, single-file)."""

import json
from pathlib import Path
from typing import Any, Dict, List

from aegisseal import __version__
from aegisseal.scanning.detectors import Finding
from aegisseal.utils.ids import stable_sort_results


def generate_html_report(
    findings: List[Finding],
    scanned_files: int,
    sarif_data: Dict[str, Any],
    suppressed_count: int = 0,
) -> str:
    """
    Generate a single-file HTML report with embedded SARIF data.

    NO timestamps, NO random IDs - completely deterministic output.

    Args:
        findings: List of findings
        scanned_files: Number of files scanned
        sarif_data: SARIF report data to embed
        suppressed_count: Number of findings suppressed by baseline

    Returns:
        HTML report as string
    """
    # Sort findings for deterministic display
    findings = stable_sort_results(findings)

    # Count by severity (deterministic order)
    severity_counts = {
        "critical": sum(1 for f in findings if f.severity.lower() == "critical"),
        "high": sum(1 for f in findings if f.severity.lower() == "high"),
        "medium": sum(1 for f in findings if f.severity.lower() == "medium"),
        "low": sum(1 for f in findings if f.severity.lower() == "low"),
    }

    # Embed SARIF data as JSON (deterministic encoding)
    sarif_json = json.dumps(
        sarif_data,
        indent=None,  # Compact for embedding
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=False,
    )

    # Generate HTML (no timestamps, no random IDs)
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
            display: flex;
            gap: 20px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .filters label {{
            display: flex;
            align-items: center;
            gap: 5px;
            cursor: pointer;
        }}

        .filters input[type="checkbox"] {{
            cursor: pointer;
        }}

        .findings-table {{
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        thead {{
            background: var(--bg-tertiary);
        }}

        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--border-color);
        }}

        td {{
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
        }}

        tbody tr:hover {{
            background: var(--bg-tertiary);
        }}

        .severity-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: bold;
            text-transform: uppercase;
            display: inline-block;
        }}

        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: black; }}
        .badge-low {{ background: var(--low); color: white; }}

        .file-path {{
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }}

        .line-num {{
            color: var(--text-secondary);
            font-family: 'Courier New', monospace;
        }}

        .rule-id {{
            font-family: 'Courier New', monospace;
            color: var(--text-secondary);
            font-size: 0.85rem;
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

        .no-findings {{
            padding: 40px;
            text-align: center;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Aegis Seal Security Report</h1>
            <div class="version">Version {__version__}</div>
        </header>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{len(findings)}</div>
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
            <strong>Filter:</strong>
            <label><input type="checkbox" class="severity-filter" value="critical" checked> Critical</label>
            <label><input type="checkbox" class="severity-filter" value="high" checked> High</label>
            <label><input type="checkbox" class="severity-filter" value="medium" checked> Medium</label>
            <label><input type="checkbox" class="severity-filter" value="low" checked> Low</label>
        </div>

        <div class="findings-table" id="findings-container"></div>

        <footer>
            <p>Generated by Aegis Seal v{__version__}</p>
            <p>SARIF data embedded for programmatic access</p>
        </footer>
    </div>

    <script id="sarif-data" type="application/json">{sarif_json}</script>

    <script>
        // Load SARIF data
        const sarifData = JSON.parse(document.getElementById('sarif-data').textContent);

        // Extract findings from SARIF
        const results = sarifData.runs[0].results || [];
        const rules = sarifData.runs[0].tool.driver.rules || [];

        // Convert SARIF to display format
        const findings = results.map(result => {{
            const rule = rules[result.ruleIndex] || {{}};
            const location = result.locations[0].physicalLocation;
            const severity = (result.properties && result.properties['aegis:severity']) ||
                           (result.level === 'error' ? 'high' : result.level);

            return {{
                file: location.artifactLocation.uri,
                line: location.region.startLine,
                ruleId: result.ruleId,
                ruleName: rule.name || result.ruleId,
                severity: severity,
                message: result.message.text
            }};
        }});

        function renderFindings() {{
            const container = document.getElementById('findings-container');
            const checkedSeverities = Array.from(document.querySelectorAll('.severity-filter:checked'))
                .map(cb => cb.value);

            const filtered = findings.filter(f => checkedSeverities.includes(f.severity.toLowerCase()));

            if (filtered.length === 0) {{
                container.innerHTML = '<div class="no-findings">No findings match the current filters.</div>';
                return;
            }}

            let html = '<table><thead><tr>';
            html += '<th>File</th>';
            html += '<th>Line</th>';
            html += '<th>Rule ID</th>';
            html += '<th>Severity</th>';
            html += '<th>Description</th>';
            html += '</tr></thead><tbody>';

            filtered.forEach(f => {{
                html += '<tr>';
                html += `<td class="file-path">${{escapeHtml(f.file)}}</td>`;
                html += `<td class="line-num">${{f.line}}</td>`;
                html += `<td class="rule-id">${{f.ruleId}}</td>`;
                html += `<td><span class="severity-badge badge-${{f.severity.toLowerCase()}}">${{f.severity}}</span></td>`;
                html += `<td>${{escapeHtml(f.message)}}</td>`;
                html += '</tr>';
            }});

            html += '</tbody></table>';
            container.innerHTML = html;
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Initial render
        renderFindings();

        // Add filter listeners
        document.querySelectorAll('.severity-filter').forEach(cb => {{
            cb.addEventListener('change', renderFindings);
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
    from aegisseal.utils.io import write_text_atomic

    write_text_atomic(output_path, html_content)
