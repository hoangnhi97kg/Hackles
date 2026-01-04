"""DA Sessions on Non-DCs"""

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
    name="DA Sessions on Non-DCs",
    category="Lateral Movement",
    default=True,
    severity=Severity.CRITICAL,
)
def get_da_sessions_non_dcs(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Domain Admin sessions on non-Domain Controller computers (credential theft opportunity)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-512'
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(dc_group:Group)
        WHERE dc_group.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN c.name AS computer, c.operatingsystem AS os,
           u.name AS domain_admin, c.enabled AS enabled
    ORDER BY u.name, c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("DA Sessions on Non-DCs", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} DA session(s) on non-DC computers")

    if results:
        print_warning("[!] CRITICAL: Domain Admin credentials can be stolen from these computers!")
        unique_computers = len(set(r["computer"] for r in results))
        unique_das = len(set(r["domain_admin"] for r in results))
        print_warning(f"    {unique_das} Domain Admin(s) on {unique_computers} computer(s)")
        print_table(
            ["Computer", "OS", "Domain Admin", "Enabled"],
            [[r["computer"], r["os"], r["domain_admin"], r["enabled"]] for r in results],
        )
        print_abuse_info("CredentialTheft", results, extract_domain(results, domain))

    return result_count
