"""Non-admin owners of high-value objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_section
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Non-Admin Owners of High-Value Objects",
    category="ACL Abuse",
    default=True,
    severity=Severity.MEDIUM,
)
def get_non_admin_owners(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find non-admin principals that own high-value objects.

    Object owners have implicit full control over objects they own.
    Non-admin users owning high-value objects is a privilege escalation risk.
    """
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:Owns]->(target)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    AND NOT n.objectid ENDS WITH '-548'  // Account Operators
    AND NOT n.objectid ENDS WITH '-549'  // Server Operators
    AND NOT n.objectid ENDS WITH '-550'  // Print Operators
    AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
    AND n.name IS NOT NULL AND n.name <> ''
    AND (target:User OR target:Group OR target:Computer OR target:GPO)
    AND (target.highvalue = true OR target:Tag_Tier_Zero OR target.admincount = true)
    {domain_filter}
    RETURN n.name AS owner,
           {node_type("n")} AS owner_type,
           target.name AS owned_object,
           {node_type("target")} AS object_type
    ORDER BY n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Non-Admin Owners of High-Value Objects", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} non-admin owner(s) of high-value objects")

    if results:
        print_warning("[!] Non-admins own high-value objects - review ownership assignments")
        print_table(
            ["Owner", "Owner Type", "Owned Object", "Object Type"],
            [[r["owner"], r["owner_type"], r["owned_object"], r["object_type"]] for r in results],
        )
        print_abuse_section(results, "Owns")

    return result_count
