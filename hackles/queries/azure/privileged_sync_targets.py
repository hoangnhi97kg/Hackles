"""Privileged accounts that may be synced to Azure AD."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Privileged Accounts Synced to Azure",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.HIGH,
)
def get_privileged_sync_targets(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find privileged accounts that appear to be synced to Azure AD.

    Privileged on-prem accounts synced to Azure AD expand the attack surface.
    If Azure is compromised, these accounts become targets for password spray
    or token theft attacks that could impact on-prem infrastructure.
    """
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Look for privileged users that have Azure-related attributes or naming
    # In practice, synced users often have specific attributes set
    query = f"""
    MATCH (u:User)-[:MemberOf*1..]->(g:Group)
    WHERE (g.highvalue = true OR g:Tag_Tier_Zero OR g.admincount = true
           OR g.objectid ENDS WITH '-512'
           OR g.objectid ENDS WITH '-519'
           OR g.objectid ENDS WITH '-544')
    AND u.enabled = true
    AND NOT u.name STARTS WITH 'KRBTGT@'
    {domain_filter}
    WITH DISTINCT u, collect(DISTINCT g.name) AS priv_groups
    RETURN u.name AS user,
           u.displayname AS display_name,
           size(priv_groups) AS priv_group_count,
           priv_groups[0..3] AS sample_groups
    ORDER BY priv_group_count DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Privileged Accounts Synced to Azure", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} privileged account(s) potentially synced")

    if results:
        print_warning("[!] These privileged accounts may be synced to Azure AD")
        print_warning("    Consider: Are these accounts excluded from Azure AD sync?")
        print_table(
            ["User", "Display Name", "Priv Groups", "Sample Groups"],
            [
                [
                    r["user"],
                    r.get("display_name") or "N/A",
                    r["priv_group_count"],
                    ", ".join(r.get("sample_groups") or []),
                ]
                for r in results
            ],
        )

    return result_count
