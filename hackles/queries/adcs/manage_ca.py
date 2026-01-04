"""ADCS ManageCA Rights (ESC7)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS ManageCA Rights (ESC7)", category="ADCS", default=True, severity=Severity.CRITICAL
)
def get_manage_ca(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find non-admin principals with ManageCA rights (ESC7)"""
    domain_filter = "AND toUpper(ca.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:ManageCA]->(ca:EnterpriseCA)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'
    AND NOT n.objectid ENDS WITH '-519'
    {domain_filter}
    RETURN n.name AS principal, {node_type('n')} AS type, ca.name AS ca
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ManageCA Rights (ESC7)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ManageCA right(s) for non-admins")

    if results:
        print_warning("ManageCA allows enabling vulnerable templates or approving requests!")
        print_table(
            ["Principal", "Type", "Certificate Authority"],
            [[r["principal"], r["type"], r["ca"]] for r in results],
        )
        print_abuse_info("ADCSESC7", results, domain)

    return result_count
