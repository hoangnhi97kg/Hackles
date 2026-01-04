"""ADCS ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag"""

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
    name="ADCS ESC6 - SAN Flag Enabled", category="ADCS", default=True, severity=Severity.CRITICAL
)
def get_esc6_san_flag(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC6 vulnerable configurations - EDITF_ATTRIBUTESUBJECTALTNAME2 flag.

    ESC6 occurs when a CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled,
    allowing requesters to specify arbitrary SANs in certificate requests.
    This enables domain privilege escalation via any template that allows enrollment.
    """
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # ESC6a - direct enrollment to CA with SAN flag
    query_6a = f"""
    MATCH (n)-[:ADCSESC6a]->(ca:EnterpriseCA)
    OPTIONAL MATCH (t:CertTemplate)-[:PublishedTo]->(ca)
    WHERE t.authenticationenabled = true
    {domain_filter}
    WITH n, ca, COLLECT(DISTINCT t.name)[0..3] AS usable_templates
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        ca.name AS ca_name,
        usable_templates,
        'ESC6a' AS variant
    ORDER BY ca.name, n.name
    LIMIT 50
    """
    results_6a = bh.run_query(query_6a, params)

    # ESC6b - via template to CA with SAN flag
    query_6b = f"""
    MATCH (n)-[:ADCSESC6b]->(ca:EnterpriseCA)
    OPTIONAL MATCH (t:CertTemplate)-[:PublishedTo]->(ca)
    WHERE t.authenticationenabled = true
    {domain_filter}
    WITH n, ca, COLLECT(DISTINCT t.name)[0..3] AS usable_templates
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        ca.name AS ca_name,
        usable_templates,
        'ESC6b' AS variant
    ORDER BY ca.name, n.name
    LIMIT 50
    """
    results_6b = bh.run_query(query_6b, params)

    results = results_6a + results_6b
    result_count = len(results)

    if not print_header("ADCS ESC6 - SAN Flag Enabled", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC6 path(s)")

    if results:
        print_warning(
            "[!] CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag - arbitrary SAN injection possible"
        )
        print_table(
            ["Principal", "Type", "Certificate Authority", "Usable Templates", "Variant"],
            [
                [
                    r["principal"],
                    r["type"],
                    r["ca_name"],
                    r.get("usable_templates", []),
                    r["variant"],
                ]
                for r in results
            ],
        )
        print_abuse_info("ADCSESC6", results, extract_domain(results, domain))

    return result_count
