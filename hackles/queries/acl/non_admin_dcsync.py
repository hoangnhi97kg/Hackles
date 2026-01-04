"""Non-Admin DCSync Principals"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Non-Admin DCSync Principals",
    category="ACL Abuse",
    default=True,
    severity=Severity.CRITICAL,
)
def get_non_admin_dcsync(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find principals with DCSync rights who are NOT Domain Admins"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain)
    WHERE (n:User OR n:Group OR n:Computer)
    AND NOT EXISTS {{
        MATCH (n)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
    }}
    {domain_filter}
    WITH n, d
    MATCH (n)-[r:GetChanges|GetChangesAll]->(d)
    WITH n, d, collect(type(r)) AS rights
    WHERE 'GetChanges' IN rights OR 'GetChangesAll' IN rights
    RETURN n.name AS principal, {node_type('n')} AS type, d.name AS domain,
           'GetChanges' IN rights AS has_getchanges,
           'GetChangesAll' IN rights AS has_getchangesall,
           n.enabled AS enabled
    ORDER BY type, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Non-Admin DCSync Principals", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} non-admin principal(s) with DCSync rights")

    if results:
        print_warning("[!] CRITICAL: These principals can DCSync but are NOT Domain Admins!")
        print_warning(
            "    Often overlooked in security reviews. May be service accounts or misconfigurations."
        )

        # Count by type
        users = sum(1 for r in results if r["type"] == "User")
        groups = sum(1 for r in results if r["type"] == "Group")
        computers = sum(1 for r in results if r["type"] == "Computer")
        print_warning(f"    Breakdown: {users} users, {groups} groups, {computers} computers")

        print_table(
            ["Principal", "Type", "Domain", "GetChanges", "GetChangesAll", "Enabled"],
            [
                [
                    r["principal"],
                    r["type"],
                    r["domain"],
                    r["has_getchanges"],
                    r["has_getchangesall"],
                    r["enabled"],
                ]
                for r in results
            ],
        )
        print_abuse_info(
            "DCSync",
            [{"principal": r["principal"]} for r in results],
            extract_domain(results, domain),
        )

    return result_count
