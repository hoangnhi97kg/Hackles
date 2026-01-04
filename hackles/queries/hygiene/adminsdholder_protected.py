"""AdminSDHolder Protected Objects"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="AdminSDHolder Protected Objects",
    category="Security Hygiene",
    default=False,
    severity=Severity.INFO,
)
def get_adminsdholder_protected(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Objects protected by AdminSDHolder (admincount=true)"""
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n {{admincount: true}})
    {domain_filter}
    RETURN {node_type('n')} AS type, n.name AS name
    ORDER BY {node_type('n')}, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AdminSDHolder Protected Objects", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} AdminSDHolder-protected object(s)")

    if results:
        print_table(["Type", "Name"], [[r["type"], r["name"]] for r in results])

    return result_count
