"""Local Admin Rights"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Local Admin Rights", category="Lateral Movement", default=True, severity=Severity.MEDIUM
)
def get_local_admin_rights(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get users/groups with local admin rights on computers"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:AdminTo]->(c:Computer)
    WHERE (n:User OR n:Group)
    AND (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type('n')} AS type,
        c.name AS computer,
        c.operatingsystem AS os
    ORDER BY n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Local Admin Rights", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} local admin relationship(s) (non-DA, limit 100)")

    if results:
        print_table(
            ["Principal", "Type", "Admin On", "OS"],
            [[r["principal"], r["type"], r["computer"], r["os"]] for r in results],
        )

    return result_count
