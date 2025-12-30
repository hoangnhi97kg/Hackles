"""Coercion to Unconstrained Delegation Chain"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain


if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="Coercion to Unconstrained Chain",
    category="Delegation",
    default=True,
    severity=Severity.CRITICAL
)
def get_coercion_chain(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find DC -> Unconstrained Delegation attack chains for TGT capture"""
    domain_filter = "AND toUpper(dc.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (dc:Computer)-[:MemberOf*1..]->(dcGroup:Group)
    WHERE dcGroup.objectid ENDS WITH '-516'
    MATCH (uc:Computer {{unconstraineddelegation: true, enabled: true}})
    WHERE NOT EXISTS {{
        MATCH (uc)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN DISTINCT dc.name AS dc, uc.name AS unconstrained_target,
           dc.operatingsystem AS dc_os, uc.operatingsystem AS uc_os
    ORDER BY dc.name, uc.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Coercion to Unconstrained Chain", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} coercion chain(s)")

    if results:
        print_warning("[!] ATTACK CHAIN: Coerce DC -> Relay to Unconstrained -> Capture DC$ TGT!")
        print_warning("[!] DC TGT = DCSync rights = Full domain compromise!")
        print_table(
            ["Domain Controller", "Unconstrained Target", "DC OS", "Target OS"],
            [[r["dc"], r["unconstrained_target"], r["dc_os"], r["uc_os"]] for r in results]
        )
        print()
        print("    Attack steps:")
        print("    1. Set up Rubeus/Krbrelayx listener on unconstrained delegation system")
        print("    2. Coerce DC authentication (PrinterBug/PetitPotam)")
        print("    3. Capture DC$ TGT when it authenticates")
        print("    4. Use DC$ TGT for DCSync attack")
        print()
        print_abuse_info("UnconstrainedDelegation", results, extract_domain(results, domain))

    return result_count
