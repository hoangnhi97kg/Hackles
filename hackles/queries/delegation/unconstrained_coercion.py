"""Unconstrained Delegation Targets"""

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
    name="Unconstrained Delegation Targets",
    category="Delegation",
    default=True,
    severity=Severity.HIGH,
)
def get_unconstrained_coercion(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find unconstrained delegation targets for coercion attacks"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true}})
    WHERE c.enabled = true
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN
        c.name AS computer,
        c.operatingsystem AS os,
        c.enabled AS enabled
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Unconstrained Delegation Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} unconstrained delegation target(s) for coercion")

    if results:
        print_warning("[!] Coerce authentication to these hosts to capture TGTs!")
        print_warning("[!] Use PrinterBug/PetitPotam to coerce DC auth -> capture DC$ TGT!")
        print_table(
            ["Computer", "OS", "Enabled"], [[r["computer"], r["os"], r["enabled"]] for r in results]
        )
        print_abuse_info("UnconstrainedDelegation", results, extract_domain(results, domain))

    return result_count
