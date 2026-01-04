"""Domain Users Dangerous ACLs"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Domain Users Dangerous ACLs",
    category="ACL Abuse",
    default=True,
    severity=Severity.CRITICAL,
)
def get_domain_users_dangerous_acls(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Dangerous ACL rights held by Domain Users group"""
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(g:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword|AddMember|AllExtendedRights]->(n)
    WHERE g.objectid ENDS WITH '-513'
    {domain_filter}
    RETURN type(r) AS edge,
           {node_type('n')} AS target_type,
           n.name AS target
    ORDER BY edge, target
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Domain Users Dangerous ACLs", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} dangerous ACL(s) for Domain Users")

    if results:
        print_warning("[!] ANY authenticated user has these rights!")
        print_table(
            ["Edge Type", "Target Type", "Target"],
            [[r["edge"], r["target_type"], r["target"]] for r in results],
        )

    return result_count
