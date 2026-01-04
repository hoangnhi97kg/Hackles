"""AddAllowedToAct (RBCD Setup)"""

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
    name="AddAllowedToAct (RBCD Setup)",
    category="ACL Abuse",
    default=True,
    severity=Severity.MEDIUM,
)
def get_add_allowed_to_act(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find principals with AddAllowedToAct permission (can set up RBCD attacks)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:AddAllowedToAct]->(c:Computer)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN
        n.name AS principal,
        CASE WHEN n:User THEN 'User' WHEN n:Computer THEN 'Computer' WHEN n:Group THEN 'Group' ELSE 'Other' END AS principal_type,
        c.name AS target,
        c.operatingsystem AS os
    ORDER BY n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AddAllowedToAct (RBCD Setup)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} AddAllowedToAct permission(s)")

    if results:
        print_warning("[!] AddAllowedToAct allows setting up RBCD attacks for impersonation!")
        print_table(
            ["Principal", "Type", "Target Computer", "OS"],
            [[r["principal"], r["principal_type"], r["target"], r["os"]] for r in results],
        )
        print_abuse_info("AddAllowedToAct", results, extract_domain(results, domain))

    return result_count
