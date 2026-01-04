"""Owned Local Admin Rights"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Owned Local Admin Rights", category="Owned", default=True, severity=Severity.MEDIUM
)
def get_owned_local_admin(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find computers where owned principals have local admin rights"""
    from_owned_filter = (
        "AND toUpper(owned.name) = toUpper($from_owned)" if config.from_owned else ""
    )
    params = {"from_owned": config.from_owned} if config.from_owned else {}

    query = f"""
    MATCH (owned)-[:AdminTo|MemberOf*1..3]->(c:Computer)
    WHERE (owned:Tag_Owned OR 'owned' IN owned.system_tags OR owned.owned = true)
    {from_owned_filter}
    RETURN owned.name AS owned_principal, {node_type('owned')} AS owned_type,
           c.name AS computer, c.operatingsystem AS os
    ORDER BY owned.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Owned Local Admin Rights", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} local admin relationship(s)")

    if results:
        print_table(
            ["Owned Principal", "Type", "Computer", "OS"],
            [[r["owned_principal"], r["owned_type"], r["computer"], r["os"]] for r in results],
        )

    return result_count
