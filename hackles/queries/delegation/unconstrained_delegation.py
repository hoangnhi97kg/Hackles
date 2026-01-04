"""Unconstrained Delegation"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Unconstrained Delegation", category="Delegation", default=True, severity=Severity.HIGH
)
def get_unconstrained_delegation(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get computers with unconstrained delegation (excluding DCs)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true}})
    WHERE NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN
        c.name AS name,
        c.operatingsystem AS os,
        c.enabled AS enabled
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Unconstrained Delegation (Non-DC)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with unconstrained delegation")

    if results:
        print_table(
            ["Computer", "Operating System", "Enabled"],
            [[r["name"], r["os"], r["enabled"]] for r in results],
        )
        print_abuse_info("UnconstrainedDelegation", results, extract_domain(results, domain))

    # Also show DCs with unconstrained delegation (INFO only, no severity)
    print_header("Domain Controllers (Unconstrained Delegation)")
    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true}})-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    {domain_filter}
    RETURN DISTINCT
        c.name AS name,
        c.operatingsystem AS os
    ORDER BY c.name
    """
    dc_results = bh.run_query(query, params)
    print_subheader(f"Found {len(dc_results)} domain controller(s)")

    if dc_results:
        print_table(
            ["Domain Controller", "Operating System"], [[r["name"], r["os"]] for r in dc_results]
        )

    return result_count
