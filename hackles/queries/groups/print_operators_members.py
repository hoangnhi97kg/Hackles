"""Print Operators Members"""

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
    name="Print Operators Members",
    category="Dangerous Groups",
    default=True,
    severity=Severity.HIGH,
)
def get_print_operators_members(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find members of Print Operators group (can load drivers on DCs)"""
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)
    WHERE g.objectid ENDS WITH '-550'
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
    results = [r for r in results if r.get("member")]
    result_count = len(results)

    if not print_header("Print Operators Members", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Print Operators member(s)")

    if results:
        print_warning("[!] Print Operators can load kernel drivers on DCs -> privilege escalation!")
        print_table(
            ["Group", "Member", "Type", "Enabled"],
            [[r["group_name"], r["member"], r["member_type"], r["enabled"]] for r in results],
        )
        print_abuse_info("PrintOperators", results, extract_domain(results, domain))

    return result_count
