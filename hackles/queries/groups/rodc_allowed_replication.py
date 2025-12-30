"""Allowed RODC Password Replication Group Members"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Allowed RODC Password Replication Group",
    category="Dangerous Groups",
    default=True,
    severity=Severity.MEDIUM
)
def get_rodc_allowed_replication(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find members of Allowed RODC Password Replication Group.

    Members of this group have their passwords cached on Read-Only Domain Controllers.
    If an RODC is compromised, these credentials can be extracted.
    """
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # RID -571 is "Allowed RODC Password Replication Group"
    query = f"""
    MATCH (g:Group)
    WHERE g.objectid ENDS WITH '-571'
    OPTIONAL MATCH (m)-[:MemberOf*1..]->(g)
    WHERE (m:User OR m:Computer OR m:Group)
    {domain_filter}
    RETURN DISTINCT
        g.name AS group_name,
        m.name AS member,
        CASE WHEN m:User THEN 'User' WHEN m:Computer THEN 'Computer' WHEN m:Group THEN 'Group' ELSE 'Other' END AS member_type,
        m.enabled AS enabled,
        COALESCE(m.admincount, false) AS admincount
    ORDER BY m.admincount DESC, m.name
    """
    results = bh.run_query(query, params)
    results = [r for r in results if r.get("member")]
    result_count = len(results)

    if not print_header("Allowed RODC Password Replication Group", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} member(s) in Allowed RODC Password Replication Group")

    if results:
        admin_members = [r for r in results if r.get("admincount")]
        if admin_members:
            print_warning("[!] CRITICAL: Privileged accounts in RODC replication group - passwords cached on RODCs!")
        else:
            print_warning("[*] Members have passwords cached on RODCs - review for sensitive accounts")
        print_table(
            ["Member", "Type", "Enabled", "AdminCount"],
            [[r["member"], r["member_type"], r["enabled"], r["admincount"]] for r in results]
        )

    return result_count
