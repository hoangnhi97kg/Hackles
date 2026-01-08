"""Owned Group Memberships"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Owned Group Memberships", category="Owned", default=True, severity=Severity.INFO
)
def get_owned_group_memberships(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find group memberships of owned principals"""
    from_owned_filter = (
        "AND toUpper(owned.name) = toUpper($from_owned)" if config.from_owned else ""
    )
    params = {"from_owned": config.from_owned} if config.from_owned else {}

    query = f"""
    MATCH (owned)-[:MemberOf*1..3]->(g:Group)
    WHERE (owned:Tag_Owned OR 'owned' IN owned.system_tags OR owned.owned = true)
    // Exclude implicit system groups (not actionable for pentesting)
    AND NOT g.objectid = 'S-1-1-0'        // EVERYONE
    AND NOT g.objectid = 'S-1-5-11'       // AUTHENTICATED USERS
    AND NOT g.name STARTS WITH 'EVERYONE@'
    AND NOT g.name STARTS WITH 'AUTHENTICATED USERS@'
    {from_owned_filter}
    RETURN owned.name AS owned_principal, {node_type("owned")} AS owned_type,
           g.name AS group_name,
           CASE WHEN 'admin_tier_0' IN g.system_tags THEN 'Yes' ELSE 'No' END AS tier_zero
    ORDER BY tier_zero DESC, owned.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Owned Group Memberships", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} group membership(s)")

    if results:
        print_table(
            ["Owned Principal", "Type", "Group", "Tier Zero?"],
            [
                [r["owned_principal"], r["owned_type"], r["group_name"], r["tier_zero"]]
                for r in results
            ],
        )

    return result_count
