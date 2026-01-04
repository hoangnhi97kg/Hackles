"""Constrained Delegation (Dangerous SPNs)"""

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
    name="Constrained Delegation (Dangerous SPNs)",
    category="Delegation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_constrained_delegation_dangerous(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Constrained delegation to dangerous services (LDAP, CIFS, HOST on DCs)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:AllowedToDelegate]->(c:Computer)
    WHERE n.allowedtodelegate IS NOT NULL
      AND ANY(spn IN n.allowedtodelegate WHERE
          toUpper(spn) CONTAINS 'LDAP' OR
          toUpper(spn) CONTAINS 'CIFS' OR
          toUpper(spn) CONTAINS 'HOST')
    {domain_filter}
    OPTIONAL MATCH (c)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    WITH n, c, n.allowedtodelegate AS spns, CASE WHEN g IS NOT NULL THEN 'YES' ELSE 'NO' END AS is_dc
    RETURN DISTINCT n.name AS principal, c.name AS target, spns AS delegation_targets, is_dc
    ORDER BY is_dc DESC, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Constrained Delegation (Dangerous Services)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} dangerous constrained delegation(s)")

    if results:
        dc_count = sum(1 for r in results if r.get("is_dc") == "YES")
        if dc_count:
            print_warning(f"[!] {dc_count} delegate to Domain Controllers - can lead to DCSync!")
        print_table(
            ["Principal", "Target", "Delegation SPNs", "Is DC?"],
            [[r["principal"], r["target"], r["delegation_targets"], r["is_dc"]] for r in results],
        )
        print_abuse_info("ConstrainedDelegation", results, extract_domain(results, domain))

    return result_count
