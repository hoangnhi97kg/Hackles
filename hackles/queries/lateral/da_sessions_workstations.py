"""DA Sessions on Workstations"""

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
    name="DA Sessions on Workstations",
    category="Lateral Movement",
    default=True,
    severity=Severity.HIGH,
)
def get_da_sessions_workstations(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Domain Admin sessions on non-DC computers (credential harvesting targets)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
    WHERE (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519')
    AND c.enabled = true
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(dc:Group)
        WHERE dc.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN DISTINCT
        u.name AS admin_user,
        c.name AS computer,
        c.operatingsystem AS os,
        g.name AS admin_group
    ORDER BY u.name, c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("DA Sessions on Workstations", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Domain Admin session(s) on non-DC computers")

    if results:
        unique_computers = len(set(r["computer"] for r in results))
        unique_admins = len(set(r["admin_user"] for r in results))
        print_warning(
            f"[!] {unique_admins} admin(s) have sessions on {unique_computers} workstation(s) - CREDENTIAL THEFT TARGETS!"
        )

        print_table(
            ["Admin User", "Computer", "OS", "Admin Group"],
            [[r["admin_user"], r["computer"], r["os"], r["admin_group"]] for r in results],
        )
        print_abuse_info("CredentialTheft", results, extract_domain(results, domain))

    return result_count
