"""Shadow Admins (Nested Indirect Privileges)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Shadow Admins (Nested)", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_shadow_admins(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find users with indirect admin rights through nested group memberships"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)-[:MemberOf*2..]->(g:Group)-[:AdminTo]->(c:Computer)
    WHERE u.admincount = false OR u.admincount IS NULL
    {domain_filter}
    WITH u, COLLECT(DISTINCT c.name)[0..5] AS sample_computers, count(DISTINCT c) AS admin_count
    WHERE admin_count > 0
    RETURN u.name AS user, admin_count AS computers_admin_to, sample_computers
    ORDER BY admin_count DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Shadow Admins (Nested Group Memberships)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} user(s) with indirect admin rights")

    if results:
        print_warning("[!] These users have admin rights through NESTED group memberships!")
        print_warning("    They may not appear as admins in direct queries.")

        total_rights = sum(r["computers_admin_to"] for r in results)
        print_warning(
            f"    Total: {result_count} users with {total_rights} indirect admin relationships"
        )

        print_table(
            ["User", "Count", "Sample Computers"],
            [[r["user"], r["computers_admin_to"], r["sample_computers"]] for r in results],
        )

    return result_count
