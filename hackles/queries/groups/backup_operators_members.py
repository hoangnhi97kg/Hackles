"""Backup Operators Members"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_for_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Backup Operators Members",
    category="Dangerous Groups",
    default=True,
    severity=Severity.HIGH,
)
def get_backup_operators_members(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find members of Backup Operators group (can backup SAM/NTDS.dit)"""
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)
    WHERE g.objectid ENDS WITH '-551'
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

    if not print_header("Backup Operators Members", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Backup Operators member(s)")

    if results:
        print_warning("[!] Backup Operators can backup NTDS.dit and SAM -> extract all hashes!")
        print_table(
            ["Group", "Member", "Type", "Enabled"],
            [[r["group_name"], r["member"], r["member_type"], r["enabled"]] for r in results],
        )
        print_abuse_for_query("backup_operators", results, target_key="member")

    return result_count
