"""ADCS ESC1 Vulnerable Templates"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS ESC1 Vulnerable Templates", category="ADCS", default=True, severity=Severity.CRITICAL
)
def get_esc1_vulnerable(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get ESC1 vulnerable certificate templates"""
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:ADCSESC1]->(m:CertTemplate)
    OPTIONAL MATCH (m)-[:PublishedTo]->(ca:EnterpriseCA)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        m.name AS template,
        ca.name AS ca
    ORDER BY m.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC1 - Vulnerable Templates", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC1 path(s) (limit 100)")

    if results:
        print_table(
            ["Principal", "Type", "Vulnerable Template", "CA"],
            [[r["principal"], r["type"], r["template"], r.get("ca", "Unknown")] for r in results],
        )
        print_abuse_info("ADCSESC1", results, extract_domain(results, domain))

    return result_count
