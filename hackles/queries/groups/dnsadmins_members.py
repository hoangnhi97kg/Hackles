"""DnsAdmins Members"""

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
    name="DnsAdmins Members", category="Dangerous Groups", default=True, severity=Severity.CRITICAL
)
def get_dnsadmins_members(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find members of DnsAdmins group (can inject DLL into DNS service on DC)"""
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)
    WHERE toUpper(g.name) CONTAINS 'DNSADMINS'
    OPTIONAL MATCH (m)-[:MemberOf*1..]->(g)
    WHERE (m:User OR m:Computer OR m:Group)
    {domain_filter}
    RETURN DISTINCT
        g.name AS group_name,
        m.name AS member,
        CASE WHEN m:User THEN 'User' WHEN m:Computer THEN 'Computer' WHEN m:Group THEN 'Group' ELSE 'Other' END AS member_type,
        m.enabled AS enabled
    ORDER BY g.name, m.name
    """
    results = bh.run_query(query, params)
    # Filter out NULL members (group exists but is empty)
    results = [r for r in results if r.get("member")]
    result_count = len(results)

    if not print_header("DnsAdmins Members", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} DnsAdmins member(s)")

    if results:
        print_warning(
            "[!] DnsAdmins can inject DLL into DNS service -> SYSTEM on DC -> Domain Admin!"
        )
        print_table(
            ["Group", "Member", "Type", "Enabled"],
            [[r["group_name"], r["member"], r["member_type"], r["enabled"]] for r in results],
        )
        print_abuse_info("DnsAdmins", results, extract_domain(results, domain))

    return result_count
