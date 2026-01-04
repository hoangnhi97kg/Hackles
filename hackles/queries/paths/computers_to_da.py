"""Computers with Paths to Domain Admin"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Computers with Paths to DA", category="Attack Paths", default=True, severity=Severity.HIGH
)
def get_computers_to_da(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find computers that have attack paths to Domain Admins"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)
    WHERE g.objectid ENDS WITH '-512'
    WITH g
    MATCH (c:Computer)
    WHERE c.enabled = true
    {domain_filter}
    WITH c, g
    MATCH p=shortestPath((c)-[*1..{config.max_path_depth}]->(g))
    WITH c, min(length(p)) AS path_length
    RETURN c.name AS computer, c.operatingsystem AS os,
           c.unconstraineddelegation AS unconstrained,
           path_length AS hops_to_da
    ORDER BY path_length ASC
    LIMIT {config.max_paths}
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Computers with Paths to Domain Admin", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with paths to Domain Admins")

    if results:
        print_warning("[!] Compromising these computers provides path to Domain Admin!")
        print_warning("    Prioritize patching and hardening these systems.")

        # Analyze hop distribution
        short_paths = sum(1 for r in results if r["hops_to_da"] <= 3)
        print_warning(f"    {short_paths} computer(s) are within 3 hops of DA")

        print_table(
            ["Computer", "OS", "Unconstrained Delegation", "Hops to DA"],
            [[r["computer"], r["os"], r["unconstrained"], r["hops_to_da"]] for r in results],
        )

    return result_count
