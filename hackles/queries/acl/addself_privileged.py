"""AddSelf to privileged groups detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="AddSelf to Privileged Groups",
    category="ACL Abuse",
    default=True,
    severity=Severity.HIGH,
)
def get_addself_privileged(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find principals who can add themselves to privileged groups.

    The AddSelf permission allows a principal to add themselves to a group
    without requiring AddMember rights. When targeting privileged groups,
    this enables direct privilege escalation.
    """
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:AddSelf]->(g:Group)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'
    AND NOT n.objectid ENDS WITH '-519'
    AND (g.highvalue = true OR g:Tag_Tier_Zero OR g.admincount = true
         OR g.objectid ENDS WITH '-512'
         OR g.objectid ENDS WITH '-519'
         OR g.objectid ENDS WITH '-544')
    {domain_filter}
    RETURN n.name AS principal,
           {node_type("n")} AS type,
           g.name AS target_group
    ORDER BY g.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AddSelf to Privileged Groups", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} AddSelf to privileged group(s)")

    if results:
        print_warning("[!] Can add themselves to privileged group - instant escalation!")
        print_table(
            ["Principal", "Type", "Target Group"],
            [[r["principal"], r["type"], r["target_group"]] for r in results],
        )

    return result_count
