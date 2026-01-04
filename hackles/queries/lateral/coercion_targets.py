"""Coercion Targets (DCs and Unconstrained Delegation)"""

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
    name="Coercion Targets", category="Lateral Movement", default=True, severity=Severity.HIGH
)
def get_coercion_targets(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Identify all potential coercion targets - DCs and unconstrained delegation systems"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Query for DCs (primary coercion targets for PrinterBug/PetitPotam)
    dc_query = f"""
    MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    {domain_filter}
    RETURN DISTINCT c.name AS name, 'Domain Controller' AS type, c.operatingsystem AS os
    ORDER BY c.name
    """
    dc_results = bh.run_query(dc_query, params)

    # Query for unconstrained delegation systems (TGT capture endpoints)
    ud_query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true}})
    WHERE c.enabled = true
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN c.name AS name, 'Unconstrained Delegation' AS type, c.operatingsystem AS os
    ORDER BY c.name
    """
    ud_results = bh.run_query(ud_query, params)

    # Combine results
    all_results = dc_results + ud_results
    result_count = len(all_results)

    if not print_header("Coercion Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} coercion target(s)")

    if all_results:
        print_warning("[!] DCs: Coerce with PrinterBug/PetitPotam to capture machine TGT")
        print_warning("[!] Unconstrained: Relay coerced auth here to capture TGTs")
        print_table(
            ["Target", "Type", "OS"], [[r["name"], r["type"], r["os"]] for r in all_results]
        )
        print_abuse_info("Coercion", all_results, extract_domain(all_results, domain))

    return result_count
