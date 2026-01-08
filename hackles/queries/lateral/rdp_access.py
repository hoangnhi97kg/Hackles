"""RDP Access (Non-Admin)"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="RDP Access (Non-Admin)",
    category="Lateral Movement",
    default=True,
    severity=Severity.MEDIUM,
)
def get_rdp_access(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get non-admin principals with RDP access"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:CanRDP]->(c:Computer)
    WHERE (n:User OR n:Group)
    AND (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    {domain_filter}
    RETURN n.name AS principal, {node_type("n")} AS type, c.name AS computer, c.operatingsystem AS os
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("RDP Access (Non-Admin)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} RDP access path(s)")

    if results:
        print_table(
            ["Principal", "Type", "Computer", "OS"],
            [[r["principal"], r["type"], r["computer"], r["os"]] for r in results],
        )

    return result_count
