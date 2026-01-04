"""ADCS ESC5 - PKI Object Control"""

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
    name="ADCS ESC5 - PKI Object Control", category="ADCS", default=True, severity=Severity.HIGH
)
def get_esc5_pki_object(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC5 vulnerable configurations - control over PKI objects.

    ESC5 involves having dangerous permissions over PKI objects like:
    - Certificate Authority (CA) objects
    - PKI enrollment services
    - NTAuthCertificates container
    """
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Check for control over CA objects
    query = f"""
    MATCH (n)-[r]->(ca:EnterpriseCA)
    WHERE type(r) IN ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns']
    {domain_filter.replace('WHERE', 'AND') if domain_filter else ''}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        type(r) AS permission,
        ca.name AS target
    ORDER BY ca.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC5 - PKI Object Control", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC5 path(s) (limit 100)")

    if results:
        print_warning("[!] Principals with dangerous permissions over Certificate Authorities")
        print_table(
            ["Principal", "Type", "Permission", "Target CA"],
            [[r["principal"], r["type"], r["permission"], r["target"]] for r in results],
        )
        print_abuse_info("ADCSESC5", results, extract_domain(results, domain))

    return result_count
