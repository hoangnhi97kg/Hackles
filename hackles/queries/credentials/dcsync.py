"""DCSync Privileges (Non-Admin)"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_for_query
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="DCSync Privileges (Non-Admin)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_dcsync(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get non-admin principals with DCSync privileges.

    Uses actual group membership to determine admin status (more accurate than admincount).
    Excludes legitimate principals: Domain Controllers, Enterprise Domain Controllers, etc.
    """
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Filter out legitimate groups and check actual DA/EA membership (not just admincount)
    query = f"""
    MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
    WHERE (n:User OR n:Group OR n:Computer)
    // Exclude principals that are members of Domain Admins, Enterprise Admins, or Domain Controllers
    AND NOT EXISTS {{
        MATCH (n)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' OR g.objectid ENDS WITH '-516'
    }}
    // Exclude built-in admin groups by RID
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    // Exclude legitimate replication groups/principals
    AND NOT n.name STARTS WITH 'ENTERPRISE DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'DOMAIN CONTROLLERS@'
    AND NOT n.objectid ENDS WITH '-516'  // Domain Controllers group
    AND NOT n.objectid ENDS WITH '-521'  // RODC group
    {domain_filter}
    RETURN DISTINCT
        n.name AS name,
        {node_type("n")} AS type,
        d.name AS domain
    ORDER BY n.name
    LIMIT 1000
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("DCSync Privileges (Non-Admin)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} non-admin principal(s) with DCSync rights")

    if results:
        print_warning("[!] Non-admin accounts with DCSync is a critical finding!")
        print_table(
            ["Principal", "Type", "Domain"], [[r["name"], r["type"], r["domain"]] for r in results]
        )
        print_abuse_for_query("dcsync", results)

    return result_count
