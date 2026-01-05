"""WriteOwner abuse paths for object takeover."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="WriteOwner Abuse Paths",
    category="ACL Abuse",
    default=True,
    severity=Severity.HIGH,
)
def get_write_owner(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find non-admin principals with WriteOwner rights.

    WriteOwner allows changing object ownership, enabling subsequent
    modification of the object's DACL to grant full control.
    """
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:WriteOwner]->(target)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'
    AND NOT n.objectid ENDS WITH '-519'
    AND (target:User OR target:Group OR target:Computer OR target:GPO)
    {domain_filter}
    RETURN n.name AS principal,
           {node_type("n")} AS type,
           target.name AS target,
           {node_type("target")} AS target_type
    ORDER BY n.name, target.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("WriteOwner Abuse Paths", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} WriteOwner relationship(s)")

    if results:
        print_warning("[!] Can take ownership of object, then modify DACL for full control!")
        print_table(
            ["Principal", "Type", "Target", "Target Type"],
            [[r["principal"], r["type"], r["target"], r["target_type"]] for r in results],
        )

    return result_count
