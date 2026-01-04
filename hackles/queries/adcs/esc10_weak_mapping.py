"""ADCS ESC10 - Weak Certificate Mapping"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS ESC10 - Weak Certificate Mapping",
    category="ADCS",
    default=True,
    severity=Severity.HIGH,
)
def get_esc10_weak_mapping(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC10 vulnerable configurations - weak certificate mapping.

    ESC10 exploits weak certificate mapping in the DC registry:
    - StrongCertificateBindingEnforcement = 0 or 1 (not 2)
    - CertificateMappingMethods includes UPN mapping (0x4)

    Combined with GenericWrite on a user, allows impersonation.
    """
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # ESC10a - weak mapping with GenericWrite
    query_10a = f"""
    MATCH (n)-[:ADCSESC10a]->(t)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        t.name AS target,
        'ESC10a' AS variant
    ORDER BY t.name, n.name
    LIMIT 50
    """
    results_10a = bh.run_query(query_10a, params)

    # ESC10b variant
    query_10b = f"""
    MATCH (n)-[:ADCSESC10b]->(t)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        t.name AS target,
        'ESC10b' AS variant
    ORDER BY t.name, n.name
    LIMIT 50
    """
    results_10b = bh.run_query(query_10b, params)

    results = results_10a + results_10b
    result_count = len(results)

    if not print_header("ADCS ESC10 - Weak Certificate Mapping", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC10 path(s)")

    if results:
        print_warning("[!] Weak certificate mapping enables impersonation via GenericWrite")
        print_table(
            ["Principal", "Type", "Target", "Variant"],
            [[r["principal"], r["type"], r["target"], r["variant"]] for r in results],
        )
        print_abuse_info("ADCSESC10", results, extract_domain(results, domain))

    return result_count
