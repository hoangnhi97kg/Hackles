"""Container/OU ACL Abuse"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Container/OU ACL Abuse", category="ACL Abuse", default=True, severity=Severity.MEDIUM
)
def get_container_acl_abuse(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Dangerous ACLs on OUs/Containers (inherit to child objects)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[r:GenericAll|WriteDacl|WriteOwner|Owns]->(ou:OU)
    WHERE NOT n.objectid ENDS WITH '-512'
      AND NOT n.objectid ENDS WITH '-519'
    {domain_filter}
    RETURN n.name AS principal, {node_type('n')} AS type, type(r) AS permission, ou.name AS ou_name
    ORDER BY ou.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Container/OU ACL Abuse", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} dangerous OU ACL(s)")

    if results:
        print_warning("[!] ACLs on OUs may inherit to all child objects!")
        print_table(
            ["Principal", "Type", "Permission", "OU"],
            [[r["principal"], r["type"], r["permission"], r["ou_name"]] for r in results],
        )

    return result_count
