"""Domain Admins"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(name="Domain Admins", category="Basic Info", default=True, severity=Severity.INFO)
def get_domain_admins(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get domain admins with relevant security flags"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)-[:MemberOf*1..]->(g:Group)
    WHERE (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' OR g.objectid ENDS WITH '-544')
    {domain_filter}
    RETURN DISTINCT
        u.name AS name,
        u.enabled AS enabled,
        u.hasspn AS hasspn,
        u.dontreqpreauth AS asrep,
        u.unconstraineddelegation AS unconstrained,
        u.admincount AS admincount
    ORDER BY u.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Domain Admins (RID 512/519/544)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} domain admin(s)")

    if results:
        print_table(
            ["Name", "Enabled", "HasSPN", "ASREP", "Unconstrained"],
            [
                [r["name"], r["enabled"], r["hasspn"], r["asrep"], r["unconstrained"]]
                for r in results
            ],
        )

    # Check for privileged users with SPN (Kerberoastable admins)
    spn_admins = [r for r in results if r.get("hasspn")]
    if spn_admins:
        print_warning(f"[!] {len(spn_admins)} admin(s) have SPN set (Kerberoastable)")

    # Check for ASREP roastable admins
    asrep_admins = [r for r in results if r.get("asrep")]
    if asrep_admins:
        print_warning(f"[!] {len(asrep_admins)} admin(s) have ASREP roasting enabled")

    return result_count
