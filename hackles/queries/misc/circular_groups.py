"""Circular Group Memberships"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Circular Group Memberships", category="Miscellaneous", default=True, severity=Severity.LOW
)
def get_circular_groups(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find circular group memberships (misconfigurations)"""
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(g:Group)-[:MemberOf*2..6]->(g)
    {domain_filter.replace('AND', 'WHERE') if domain_filter else ''}
    RETURN DISTINCT
        g.name AS group_name,
        [n IN nodes(p) | n.name] AS cycle_path,
        length(p) AS cycle_length
    LIMIT 20
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Circular Group Memberships", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} circular group membership(s)")

    if results:
        print_warning("Circular group memberships are misconfigurations that should be fixed!")
        print_table(
            ["Group", "Cycle Path", "Cycle Length"],
            [[r["group_name"], r["cycle_path"], r["cycle_length"]] for r in results],
        )

    return result_count
