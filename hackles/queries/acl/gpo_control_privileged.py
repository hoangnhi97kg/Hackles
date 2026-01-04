"""Non-Admin GPO Control"""

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
    name="Non-Admin GPO Control", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_gpo_control_privileged(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find non-admin principals with control over GPOs"""
    domain_filter = "AND toUpper(gpo.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(gpo:GPO)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN
        n.name AS principal,
        CASE WHEN n:User THEN 'User' WHEN n:Computer THEN 'Computer' WHEN n:Group THEN 'Group' ELSE 'Other' END AS principal_type,
        type(r) AS permission,
        gpo.name AS gpo_name
    ORDER BY n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Non-Admin GPO Control", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} non-admin GPO control relationship(s)")

    if results:
        print_warning("[!] GPO modification can lead to code execution on linked computers!")
        print_table(
            ["Principal", "Type", "Permission", "GPO Name"],
            [
                [r["principal"], r["principal_type"], r["permission"], r["gpo_name"]]
                for r in results
            ],
        )
        print_abuse_info("GPOAbuse", results, extract_domain(results, domain))

    return result_count
