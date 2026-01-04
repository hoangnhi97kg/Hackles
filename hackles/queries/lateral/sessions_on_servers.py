"""Privileged Sessions on Member Servers"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Privileged Sessions on Servers",
    category="Lateral Movement",
    default=True,
    severity=Severity.HIGH,
)
def get_sessions_on_servers(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find privileged user sessions on member servers (tier separation violation)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
    WHERE (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
           OR g.objectid ENDS WITH '-518' OR g.name =~ '(?i).*admin.*')
    AND c.operatingsystem =~ '(?i).*server.*'
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(dc_group:Group)
        WHERE dc_group.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    WITH DISTINCT c, u
    RETURN c.name AS computer, c.operatingsystem AS os,
           u.name AS privileged_user, c.enabled AS enabled
    ORDER BY u.name, c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Privileged Sessions on Member Servers", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} privileged session(s) on member servers")

    if results:
        print_warning("[!] Privileged users have sessions on member servers!")
        print_warning("    This violates tier separation - credentials can be stolen")
        print()

        # Stats
        unique_servers = len(set(r["computer"] for r in results))
        unique_users = len(set(r["privileged_user"] for r in results))
        print_warning(f"    {unique_users} privileged user(s) on {unique_servers} server(s)")
        print()

        print("    Recommendation: Implement tiered administration model")
        print("    - Tier 0: Domain Controllers only")
        print("    - Tier 1: Member servers")
        print("    - Tier 2: Workstations")
        print()

        print_table(
            ["Computer", "OS", "Privileged User", "Enabled"],
            [[r["computer"], r["os"], r["privileged_user"], r["enabled"]] for r in results],
        )
        print_abuse_info("CredentialTheft", results, extract_domain(results, domain))

    return result_count
