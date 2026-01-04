"""ADCS ESC9 - No Security Extension"""

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
    name="ADCS ESC9 - No Security Extension", category="ADCS", default=True, severity=Severity.HIGH
)
def get_esc9_no_security_ext(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC9 vulnerable configurations - CT_FLAG_NO_SECURITY_EXTENSION.

    ESC9 occurs when a certificate template has CT_FLAG_NO_SECURITY_EXTENSION flag,
    meaning the szOID_NTDS_CA_SECURITY_EXT security extension is not embedded.
    Combined with GenericWrite on a user, this enables impersonation attacks.
    """
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # ESC9a - user can enroll and has write on another user
    query_9a = f"""
    MATCH (n)-[:ADCSESC9a]->(t:CertTemplate)
    OPTIONAL MATCH (t)-[:PublishedTo]->(ca:EnterpriseCA)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        t.name AS template,
        ca.name AS ca,
        'ESC9a' AS variant
    ORDER BY t.name, n.name
    LIMIT 50
    """
    results_9a = bh.run_query(query_9a, params)

    # ESC9b variant
    query_9b = f"""
    MATCH (n)-[:ADCSESC9b]->(t:CertTemplate)
    OPTIONAL MATCH (t)-[:PublishedTo]->(ca:EnterpriseCA)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        t.name AS template,
        ca.name AS ca,
        'ESC9b' AS variant
    ORDER BY t.name, n.name
    LIMIT 50
    """
    results_9b = bh.run_query(query_9b, params)

    results = results_9a + results_9b
    result_count = len(results)

    if not print_header("ADCS ESC9 - No Security Extension", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC9 path(s)")

    if results:
        print_warning(
            "[!] Templates without security extension allow impersonation via GenericWrite"
        )
        print_table(
            ["Principal", "Type", "Template", "CA", "Variant"],
            [
                [r["principal"], r["type"], r["template"], r.get("ca", "Unknown"), r["variant"]]
                for r in results
            ],
        )
        print_abuse_info("ADCSESC9", results, extract_domain(results, domain))

    return result_count
