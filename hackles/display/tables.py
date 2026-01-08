"""Table and header display functions"""

from typing import Any, Dict, List, Optional

from prettytable import PrettyTable

from hackles.core.config import config
from hackles.core.utils import format_timestamp, is_unix_timestamp
from hackles.display.colors import Severity, colors


def print_header(
    text: str, severity: Optional[Severity] = None, result_count: Optional[int] = None
) -> bool:
    """Print a section header with optional severity indicator.

    Returns True if output should continue, False if quiet mode and no results,
    or if output format is not table (JSON/CSV/HTML mode).
    """
    # In non-table output modes, suppress all printing
    if config.output_format != "table":
        return False

    # In quiet mode, skip queries with zero results
    if config.quiet_mode and result_count is not None and result_count == 0:
        return False

    # Show severity tag only for non-INFO levels with actual findings
    show_severity = (
        severity is not None
        and severity != Severity.INFO
        and result_count is not None
        and result_count > 0
    )

    if show_severity:
        sev_tag = f"{severity.color}[{severity.label}]{colors.END} "
    else:
        sev_tag = ""
    print(f"\n{colors.BOLD}{colors.BLUE}[*] {sev_tag}{text}{colors.END}")
    return True


def print_subheader(text: str):
    """Print a sub-section header (only in table mode)"""
    if config.output_format != "table":
        return
    print(f"    {colors.GREEN}{text}{colors.END}")


def print_warning(text: str):
    """Print a warning message (only in table mode)"""
    if config.output_format != "table":
        return
    print(f"    {colors.WARNING}{text}{colors.END}")


def print_severity_summary(severity_counts: Dict[Severity, int]) -> None:
    """Print summary of findings by severity level (only in table mode)."""
    if config.output_format != "table":
        return

    # Only print if there are any findings
    has_findings = any(count > 0 for sev, count in severity_counts.items() if sev != Severity.INFO)
    if not has_findings:
        print(f"\n{colors.GREEN}[+] No security findings detected{colors.END}")
        return

    print(f"\n{colors.BOLD}[*] Findings Summary{colors.END}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            label = "query" if count == 1 else "queries"
            print(f"    {sev.color}{sev.label}{colors.END}: {count} {label} with findings")


def print_table(headers: List[str], rows: List[List[Any]], max_width: int = 65) -> None:
    """Print a formatted table with owned principal highlighting (only in table mode)."""
    if config.output_format != "table":
        return

    if not rows:
        print_warning("No results found")
        return

    table = PrettyTable()
    table.field_names = headers
    table.align = "l"
    table.max_width = max_width

    for row in rows:
        formatted_row = []
        for val in row:
            if val is None:
                formatted_row.append("-")
            elif isinstance(val, list):
                formatted_row.append(", ".join(str(v) for v in val[:3]))
                if len(val) > 3:
                    formatted_row[-1] += f" (+{len(val)-3} more)"
            elif isinstance(val, (int, float)) and is_unix_timestamp(val):
                # Auto-format Unix timestamps to readable dates
                formatted_row.append(format_timestamp(val))
            elif isinstance(val, str):
                if val in config.owned_cache:
                    is_admin = config.owned_cache[val]
                    if is_admin:
                        prefix = f"{colors.FAIL}[!]{colors.END} "  # Red for admin
                    else:
                        prefix = f"{colors.WARNING}[!]{colors.END} "  # Yellow for non-admin
                    if len(val) > max_width - 4:
                        # Guard against negative slice index when max_width is very small
                        truncate_at = max(1, max_width - 7)
                        formatted_row.append(prefix + val[:truncate_at] + "...")
                    else:
                        formatted_row.append(prefix + val)
                elif len(val) > max_width:
                    # Guard against negative slice index when max_width is very small
                    truncate_at = max(1, max_width - 3)
                    formatted_row.append(val[:truncate_at] + "...")
                else:
                    formatted_row.append(val)
            else:
                formatted_row.append(str(val))
        table.add_row(formatted_row)

    print(table)


def print_node_info(node_props: Dict[str, Any]) -> None:
    """Pretty-print node properties (only in table mode)."""
    if config.output_format != "table":
        return

    labels = node_props.get("_labels", [])

    print(f"    {colors.BOLD}Labels:{colors.END} {', '.join(labels)}")
    print(f"    {colors.BOLD}Properties:{colors.END}")

    # Show security-relevant properties first
    priority_keys = [
        "name",
        "domain",
        "objectid",
        "enabled",
        "admincount",
        "hasspn",
        "dontreqpreauth",
        "unconstraineddelegation",
    ]

    sorted_keys = []
    for key in priority_keys:
        if key in node_props:
            sorted_keys.append(key)
    for key in sorted(node_props.keys()):
        if key not in sorted_keys and key != "_labels":
            sorted_keys.append(key)

    for key in sorted_keys:
        value = node_props[key]
        if value is None:
            value_str = "-"
        elif isinstance(value, list):
            value_str = ", ".join(str(v) for v in value[:5])
            if len(value) > 5:
                value_str += f" (+{len(value)-5} more)"
        elif isinstance(value, bool):
            value_str = (
                f"{colors.GREEN}True{colors.END}" if value else f"{colors.FAIL}False{colors.END}"
            )
        else:
            value_str = str(value)

        print(f"      {colors.CYAN}{key}:{colors.END} {value_str}")
