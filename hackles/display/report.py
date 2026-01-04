"""HTML report generation for hackles"""

import html
import re
from datetime import datetime
from typing import Any, Dict, List

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Hackles Report - {date}</title>
    <meta charset="utf-8">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 40px;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }}
        h1 {{
            color: #00d9ff;
            border-bottom: 2px solid #00d9ff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #fff;
            margin-top: 30px;
        }}
        h3 {{
            margin: 20px 0 10px 0;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            user-select: none;
        }}
        h3:hover {{ opacity: 0.9; }}
        h3::before {{
            content: '\\25BC ';
            font-size: 0.7em;
            margin-right: 5px;
        }}
        h3.collapsed::before {{ content: '\\25B6 '; }}
        .critical {{ background: #dc3545; color: white; }}
        .high {{ background: #fd7e14; color: white; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; color: white; }}
        .info {{ background: #6c757d; color: white; }}
        .finding-content {{
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        .finding-content.collapsed {{
            max-height: 0 !important;
            margin: 0;
            padding: 0;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 10px 0 20px 0;
            background: #16213e;
        }}
        th {{
            background: #0f3460;
            color: #00d9ff;
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        td {{
            border-bottom: 1px solid #0f3460;
            padding: 10px 8px;
            word-break: break-word;
        }}
        tr:hover td {{ background: #1a1a40; }}
        tr.hidden {{ display: none; }}
        .summary {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}
        .stat {{
            text-align: center;
            padding: 15px;
            border-radius: 6px;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        .stat:hover {{ transform: scale(1.05); }}
        .stat.active {{ box-shadow: 0 0 0 3px #00d9ff; }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.8;
        }}
        .no-findings {{
            color: #6c757d;
            font-style: italic;
            padding: 20px;
        }}
        .controls {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 12px 15px;
            border: 2px solid #0f3460;
            border-radius: 6px;
            background: #1a1a2e;
            color: #eee;
            font-size: 1em;
        }}
        .search-box:focus {{
            outline: none;
            border-color: #00d9ff;
        }}
        .btn {{
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            transition: background 0.2s;
        }}
        .btn-primary {{
            background: #00d9ff;
            color: #1a1a2e;
        }}
        .btn-primary:hover {{ background: #00b8d9; }}
        .btn-secondary {{
            background: #0f3460;
            color: #eee;
        }}
        .btn-secondary:hover {{ background: #1a4a7a; }}
        .toc {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .toc h2 {{ margin-top: 0; }}
        .toc ul {{ column-count: 2; }}
        .toc a {{ color: #00d9ff; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}
        .pagination {{
            display: flex;
            gap: 5px;
            margin: 10px 0;
            flex-wrap: wrap;
        }}
        .pagination button {{
            padding: 5px 12px;
            border: 1px solid #0f3460;
            background: #16213e;
            color: #eee;
            cursor: pointer;
            border-radius: 4px;
        }}
        .pagination button:hover {{ background: #0f3460; }}
        .pagination button.active {{
            background: #00d9ff;
            color: #1a1a2e;
            border-color: #00d9ff;
        }}
        .pagination button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .finding {{ margin-bottom: 30px; }}
        .finding.hidden {{ display: none; }}
        .export-btn {{
            margin-left: auto;
        }}
        .table-info {{
            color: #6c757d;
            font-size: 0.9em;
            margin: 5px 0;
        }}
        footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #0f3460;
            color: #6c757d;
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .toc ul {{ column-count: 1; }}
            .controls {{ flex-direction: column; }}
            .search-box {{ width: 100%; }}
        }}
    </style>
</head>
<body>
    <h1>Hackles Security Report</h1>
    <p>Generated: {date}</p>

    <div class="summary">
        <div class="stat critical" onclick="filterBySeverity('critical')" title="Click to filter">
            <div class="stat-value">{critical}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat high" onclick="filterBySeverity('high')" title="Click to filter">
            <div class="stat-value">{high}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat medium" onclick="filterBySeverity('medium')" title="Click to filter">
            <div class="stat-value">{medium}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat low" onclick="filterBySeverity('low')" title="Click to filter">
            <div class="stat-value">{low}</div>
            <div class="stat-label">Low</div>
        </div>
        <div class="stat info" onclick="filterBySeverity('info')" title="Click to filter">
            <div class="stat-value">{info}</div>
            <div class="stat-label">Info</div>
        </div>
    </div>

    <div class="controls">
        <input type="text" class="search-box" id="searchInput" placeholder="Search findings..." onkeyup="searchFindings()">
        <button class="btn btn-secondary" onclick="expandAll()">Expand All</button>
        <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
        <button class="btn btn-secondary" onclick="clearFilters()">Clear Filters</button>
        <button class="btn btn-primary export-btn" onclick="exportCSV()">Export CSV</button>
    </div>

    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            {toc}
        </ul>
    </div>

    <h2>Findings</h2>
    <div id="findingsContainer">
        {findings}
    </div>

    <footer>
        Generated by Hackles - BloodHound CE Query Tool<br>
        Total queries executed: {total_queries}
    </footer>

    <script>
        // Search functionality
        function searchFindings() {{
            const filter = document.getElementById('searchInput').value.toLowerCase();
            const findings = document.querySelectorAll('.finding');

            findings.forEach(finding => {{
                const text = finding.textContent.toLowerCase();
                if (text.includes(filter)) {{
                    finding.classList.remove('hidden');
                }} else {{
                    finding.classList.add('hidden');
                }}
            }});
        }}

        // Filter by severity (clicking stat boxes)
        let activeSeverity = null;
        function filterBySeverity(severity) {{
            const stats = document.querySelectorAll('.stat');
            const findings = document.querySelectorAll('.finding');

            if (activeSeverity === severity) {{
                // Clear filter
                activeSeverity = null;
                stats.forEach(s => s.classList.remove('active'));
                findings.forEach(f => f.classList.remove('hidden'));
            }} else {{
                // Apply filter
                activeSeverity = severity;
                stats.forEach(s => {{
                    s.classList.toggle('active', s.classList.contains(severity));
                }});
                findings.forEach(finding => {{
                    const header = finding.querySelector('h3');
                    if (header && header.classList.contains(severity)) {{
                        finding.classList.remove('hidden');
                    }} else {{
                        finding.classList.add('hidden');
                    }}
                }});
            }}
        }}

        // Collapse/Expand functionality
        function toggleCollapse(header) {{
            header.classList.toggle('collapsed');
            const content = header.nextElementSibling;
            if (content && content.classList.contains('finding-content')) {{
                content.classList.toggle('collapsed');
            }}
        }}

        function expandAll() {{
            document.querySelectorAll('h3.collapsed').forEach(h => h.classList.remove('collapsed'));
            document.querySelectorAll('.finding-content.collapsed').forEach(c => c.classList.remove('collapsed'));
        }}

        function collapseAll() {{
            document.querySelectorAll('.finding h3').forEach(h => h.classList.add('collapsed'));
            document.querySelectorAll('.finding-content').forEach(c => c.classList.add('collapsed'));
        }}

        function clearFilters() {{
            document.getElementById('searchInput').value = '';
            activeSeverity = null;
            document.querySelectorAll('.stat').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.finding').forEach(f => f.classList.remove('hidden'));
            expandAll();
        }}

        // Pagination for tables
        function setupPagination(tableId, rowsPerPage) {{
            const table = document.getElementById(tableId);
            if (!table) return;

            const tbody = table.querySelector('tbody') || table;
            const rows = Array.from(tbody.querySelectorAll('tr')).slice(1); // Skip header
            const totalPages = Math.ceil(rows.length / rowsPerPage);

            if (totalPages <= 1) return;

            let currentPage = 1;

            function showPage(page) {{
                currentPage = page;
                rows.forEach((row, idx) => {{
                    const start = (page - 1) * rowsPerPage;
                    const end = start + rowsPerPage;
                    row.classList.toggle('hidden', idx < start || idx >= end);
                }});

                // Update pagination buttons
                const container = table.parentElement.querySelector('.pagination');
                if (container) {{
                    container.querySelectorAll('button').forEach((btn, idx) => {{
                        if (idx === 0) btn.disabled = page === 1;
                        else if (idx === container.children.length - 1) btn.disabled = page === totalPages;
                        else btn.classList.toggle('active', parseInt(btn.textContent) === page);
                    }});
                }}
            }}

            // Create pagination controls
            const paginationDiv = document.createElement('div');
            paginationDiv.className = 'pagination';

            const prevBtn = document.createElement('button');
            prevBtn.textContent = 'Prev';
            prevBtn.onclick = () => showPage(Math.max(1, currentPage - 1));
            paginationDiv.appendChild(prevBtn);

            for (let i = 1; i <= Math.min(totalPages, 10); i++) {{
                const btn = document.createElement('button');
                btn.textContent = i;
                btn.onclick = () => showPage(i);
                if (i === 1) btn.classList.add('active');
                paginationDiv.appendChild(btn);
            }}

            const nextBtn = document.createElement('button');
            nextBtn.textContent = 'Next';
            nextBtn.onclick = () => showPage(Math.min(totalPages, currentPage + 1));
            paginationDiv.appendChild(nextBtn);

            table.parentElement.insertBefore(paginationDiv, table.nextSibling);
            showPage(1);
        }}

        // Export to CSV
        function exportCSV() {{
            let csv = 'Query,Severity,Count\\n';
            document.querySelectorAll('.finding').forEach(finding => {{
                const header = finding.querySelector('h3');
                if (header) {{
                    const text = header.textContent.trim();
                    const match = text.match(/^(.+?)\\s*\\((\\d+)/);
                    if (match) {{
                        const query = match[1].trim().replace(/"/g, '""');
                        const count = match[2];
                        let severity = 'INFO';
                        ['critical', 'high', 'medium', 'low', 'info'].forEach(s => {{
                            if (header.classList.contains(s)) severity = s.toUpperCase();
                        }});
                        csv += `"${{query}}",${{severity}},${{count}}\\n`;
                    }}
                }}
            }});

            const blob = new Blob([csv], {{ type: 'text/csv' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'hackles-findings.csv';
            a.click();
            URL.revokeObjectURL(url);
        }}

        // Initialize collapsible headers
        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('.finding h3').forEach(header => {{
                header.onclick = () => toggleCollapse(header);
            }});

            // Setup pagination for large tables (>25 rows)
            document.querySelectorAll('table').forEach((table, idx) => {{
                const rows = table.querySelectorAll('tr').length - 1;
                if (rows > 25) {{
                    table.id = table.id || 'table-' + idx;
                    setupPagination(table.id, 25);
                }}
            }});
        }});
    </script>
</body>
</html>"""


def _escape_html(text) -> str:
    """Escape HTML special characters.

    Args:
        text: Any value to escape (will be converted to string)

    Returns:
        HTML-escaped string
    """
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_html_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """Generate HTML report from query results.

    Args:
        results: List of query result dicts with keys: query, severity, count, results
        output_path: Path to write HTML file
    """
    # Count findings by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    findings_html = []
    toc_items = []

    for r in results:
        sev = r.get("severity", "INFO")
        count = r.get("count", 0)

        if count > 0:
            severity_counts[sev] += 1

            # Create anchor ID (alphanumeric and hyphens only)
            anchor_id = re.sub(r"[^a-zA-Z0-9_-]", "", r["query"].lower().replace(" ", "-"))

            # Add to TOC
            toc_items.append(
                f'<li><a href="#{anchor_id}">{_escape_html(r["query"])} ({count})</a></li>'
            )

            # Build table if results exist
            result_data = r.get("results", [])
            if result_data and len(result_data) > 0:
                # Get columns from first result
                columns = list(result_data[0].keys())
                header_row = "".join(f"<th>{_escape_html(c)}</th>" for c in columns)

                # Limit to 100 rows for large result sets
                display_data = result_data[:100]
                data_row_list = []
                for row in display_data:
                    cells = "".join(f'<td>{_escape_html(row.get(c, ""))}</td>' for c in columns)
                    data_row_list.append(f"<tr>{cells}</tr>")
                data_rows = "\n".join(data_row_list)

                truncation_note = ""
                if len(result_data) > 100:
                    truncation_note = (
                        f'<p style="color: #ffc107;">Showing 100 of {len(result_data)} results</p>'
                    )

                table_html = f"""
                <table>
                    <tr>{header_row}</tr>
                    {data_rows}
                </table>
                {truncation_note}
                """
            else:
                table_html = f'<p class="no-findings">Found {count} item(s) - detailed data not available in report mode</p>'

            findings_html.append(
                f"""
            <div class="finding">
                <h3 id="{anchor_id}" class="{sev.lower()}">{_escape_html(r["query"])} ({count} finding(s))</h3>
                <div class="finding-content">
                    {table_html}
                </div>
            </div>
            """
            )

    # If no findings at all
    if not findings_html:
        findings_html.append('<p class="no-findings">No security findings detected.</p>')
        toc_items.append("<li>No findings</li>")

    html_output = HTML_TEMPLATE.format(
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_queries=len(results),
        critical=severity_counts["CRITICAL"],
        high=severity_counts["HIGH"],
        medium=severity_counts["MEDIUM"],
        low=severity_counts["LOW"],
        info=severity_counts["INFO"],
        toc="\n".join(toc_items),
        findings="\n".join(findings_html),
    )

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_output)
    except IOError as e:
        raise IOError(f"Failed to write HTML report to '{output_path}': {e}") from e


SIMPLE_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>{title} - Hackles</title>
    <meta charset="utf-8">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 40px;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }}
        h1 {{
            color: #00d9ff;
            border-bottom: 2px solid #00d9ff;
            padding-bottom: 10px;
        }}
        .info {{
            color: #6c757d;
            margin-bottom: 20px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 10px 0 20px 0;
            background: #16213e;
        }}
        th {{
            background: #0f3460;
            color: #00d9ff;
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        td {{
            border-bottom: 1px solid #0f3460;
            padding: 10px 8px;
            word-break: break-word;
        }}
        tr:hover td {{ background: #1a1a40; }}
        tr.hidden {{ display: none; }}
        .controls {{
            background: #16213e;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 10px 15px;
            border: 2px solid #0f3460;
            border-radius: 6px;
            background: #1a1a2e;
            color: #eee;
            font-size: 1em;
        }}
        .search-box:focus {{
            outline: none;
            border-color: #00d9ff;
        }}
        .btn {{
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            background: #00d9ff;
            color: #1a1a2e;
        }}
        .btn:hover {{ background: #00b8d9; }}
        footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #0f3460;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p class="info">Generated: {date} | Total: {count} result(s)</p>

    <div class="controls">
        <input type="text" class="search-box" id="searchInput" placeholder="Search..." onkeyup="searchTable()">
        <button class="btn" onclick="exportCSV()">Export CSV</button>
    </div>

    <table id="dataTable">
        <tr>{header_row}</tr>
        {data_rows}
    </table>

    <footer>Generated by Hackles - BloodHound CE Query Tool</footer>

    <script>
        function searchTable() {{
            const filter = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#dataTable tr:not(:first-child)');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.classList.toggle('hidden', !text.includes(filter));
            }});
        }}

        function exportCSV() {{
            const table = document.getElementById('dataTable');
            const rows = table.querySelectorAll('tr');
            let csv = '';
            rows.forEach(row => {{
                const cells = row.querySelectorAll('th, td');
                const rowData = Array.from(cells).map(c => '"' + c.textContent.replace(/"/g, '""') + '"');
                csv += rowData.join(',') + '\\n';
            }});
            const blob = new Blob([csv], {{ type: 'text/csv' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = '{filename}.csv';
            a.click();
            URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>"""


def generate_simple_html(
    title: str, columns: List[str], data: List[Dict[str, Any]], output_path: str
) -> None:
    """Generate a simple HTML table report for single-command output.

    Args:
        title: Report title/heading
        columns: List of column names
        data: List of dicts with data (keys should match column names or be lowercase with underscores)
        output_path: Path to write HTML file
    """
    # Build header row
    header_row = "".join(f"<th>{_escape_html(c)}</th>" for c in columns)

    # Build data rows - try multiple key formats for flexibility
    data_rows = []
    for row in data:
        cells = []
        for col in columns:
            # Try: exact match, lowercase, lowercase with underscores
            key_variants = [
                col,
                col.lower(),
                col.lower().replace(" ", "_"),
            ]
            value = None
            for key in key_variants:
                if key in row:
                    value = row[key]
                    break
            cells.append(f"<td>{_escape_html(value)}</td>")
        data_rows.append(f'<tr>{"".join(cells)}</tr>')

    # Generate filename from title
    filename = title.lower().replace(" ", "_").replace(":", "")[:30]

    html_output = SIMPLE_HTML_TEMPLATE.format(
        title=_escape_html(title),
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        count=len(data),
        header_row=header_row,
        data_rows="\n        ".join(data_rows),
        filename=filename,
    )

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_output)
    except IOError as e:
        raise IOError(f"Failed to write HTML report to '{output_path}': {e}") from e
