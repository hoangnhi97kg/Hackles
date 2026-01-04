"""Attack path display functions"""

from typing import Dict, List

from prettytable import PrettyTable

from hackles.core.config import config
from hackles.display.colors import colors
from hackles.display.tables import print_warning

# Maximum paths to display
MAX_PATHS_DISPLAY = 10


def _format_node_short(node_name: str) -> str:
    """Format a node name for compact display, removing domain suffix."""
    if "@" in node_name:
        return node_name.split("@")[0]
    return node_name


def _format_node_with_owned(node_name: str, use_short: bool = True) -> str:
    """Format a node with owned marker if applicable."""
    short_name = _format_node_short(node_name) if use_short else node_name

    if node_name in config.owned_cache:
        is_admin = config.owned_cache[node_name]
        if is_admin:
            return f"{colors.FAIL}[!]{colors.END}{short_name}"
        else:
            return f"{colors.WARNING}[!]{colors.END}{short_name}"
    return short_name


def _build_full_path_string(nodes: List[str], rels: List[str]) -> str:
    """Build a full path string with nodes and relationships.

    Example: R.ANDREWS -[MemberOf]-> DOMAIN USERS -[LocalToComputer]-> DC20
    """
    if not nodes:
        return ""

    parts = []
    for i, node in enumerate(nodes):
        # Format node (short name, with owned marker if applicable)
        node_fmt = _format_node_with_owned(node, use_short=True)
        parts.append(node_fmt)

        # Add relationship arrow if not the last node
        if i < len(rels):
            parts.append(f"-[{rels[i]}]->")

    return " ".join(parts)


def print_paths_grouped(results: List[Dict], max_display: int = MAX_PATHS_DISPLAY):
    """Display paths in a table format with full path information.

    Args:
        results: List of path dictionaries from query
        max_display: Maximum number of paths to display (default 10)
    """
    if config.output_format != "table":
        return

    if not results:
        return

    # Sort by path length
    sorted_results = sorted(results, key=lambda p: p.get("path_length", 0))

    # Limit display
    display_results = sorted_results[:max_display]
    hidden_count = len(sorted_results) - len(display_results)

    # Build table with full path information
    table = PrettyTable()
    table.field_names = ["Hops", "Attack Path"]
    table.align = "l"
    # No max_width - let the table expand to show full content

    for r in display_results:
        nodes = r.get("nodes", [])
        rels = r.get("relationships", [])
        path_len = r.get("path_length", len(nodes) - 1 if nodes else 0)

        if not nodes:
            continue

        # Build full path string with relationships
        path_str = _build_full_path_string(nodes, rels)

        table.add_row([path_len, path_str])

    print(table)

    # Show summary of hidden paths
    if hidden_count > 0:
        print(f"    {colors.GRAY}... and {hidden_count} more path(s) not shown{colors.END}")


def print_path(path_data: dict):
    """Pretty-print a single attack path in table format."""
    if config.output_format != "table":
        return

    # Wrap single path in list and use grouped display
    print_paths_grouped([path_data], max_display=1)


def print_paths_detailed(results: List[Dict], max_display: int = 5):
    """Display paths with full detail (vertical format) for important paths.

    Use this for critical paths where users need to see every step.

    Args:
        results: List of path dictionaries from query
        max_display: Maximum number of paths to show in detail
    """
    if config.output_format != "table":
        return

    if not results:
        return

    # Sort by path length
    sorted_results = sorted(results, key=lambda p: p.get("path_length", 0))
    display_results = sorted_results[:max_display]
    hidden_count = len(sorted_results) - len(display_results)

    for r in display_results:
        nodes = r.get("nodes", [])
        node_types = r.get("node_types", [])
        rels = r.get("relationships", [])

        if not nodes:
            continue

        path_len = r.get("path_length", len(nodes) - 1)
        print(f"    {colors.BOLD}Path ({path_len} hop{'s' if path_len != 1 else ''}):{colors.END}")

        for i, node in enumerate(nodes):
            type_str = f"({node_types[i]})" if i < len(node_types) else ""

            if node in config.owned_cache:
                is_admin = config.owned_cache[node]
                marker = (
                    f"{colors.FAIL}[!]{colors.END}"
                    if is_admin
                    else f"{colors.WARNING}[!]{colors.END}"
                )
                print(f"      {marker} {node} {type_str}")
            else:
                print(f"      {node} {type_str}")

            if i < len(rels):
                print(f"        {colors.CYAN}--[{rels[i]}]-->{colors.END}")

    if hidden_count > 0:
        print(f"    {colors.GRAY}... and {hidden_count} more path(s) not shown{colors.END}")


def print_paths_summary(results: List[Dict]):
    """Print a summary table of paths without full details.

    Shows unique starting nodes and their shortest path lengths.
    """
    if config.output_format != "table":
        return

    if not results:
        return

    # Group by starting node and find shortest path for each
    by_start = {}
    for r in results:
        nodes = r.get("nodes", [])
        if not nodes:
            continue
        start = nodes[0]
        path_len = r.get("path_length", len(nodes) - 1)
        target = nodes[-1] if nodes else ""

        if start not in by_start:
            by_start[start] = {"min_hops": path_len, "count": 0, "targets": set()}
        by_start[start]["count"] += 1
        by_start[start]["min_hops"] = min(by_start[start]["min_hops"], path_len)
        by_start[start]["targets"].add(target)

    # Build summary table
    table = PrettyTable()
    table.field_names = ["Source", "Paths", "Shortest", "Targets"]
    table.align = "l"

    for start, info in sorted(by_start.items(), key=lambda x: x[1]["min_hops"]):
        source_fmt = _format_node_with_owned(start)
        table.add_row([source_fmt, info["count"], f"{info['min_hops']} hops", len(info["targets"])])

    print(table)
