"""ADCS ESC4 - Template ACL Vulnerabilities"""

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
    name="ADCS ESC4 - Template ACL Abuse", category="ADCS", default=True, severity=Severity.HIGH
)
def get_esc4_template_acl(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC4 vulnerable configurations - principals with write access to certificate templates.

    ESC4 allows attackers with write permissions to certificate templates to modify
    the template configuration to enable ESC1/ESC2/ESC3 conditions.
    """
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:ADCSESC4]->(t:CertTemplate)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        t.name AS template,
        t.displayname AS display_name
    ORDER BY t.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC4 - Template ACL Abuse", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC4 path(s) (limit 100)")

    if results:
        print_warning("[!] Principals can modify certificate templates to enable ESC1/ESC2/ESC3")
        print_table(
            ["Principal", "Type", "Template", "Display Name"],
            [
                [r["principal"], r["type"], r["template"], r.get("display_name", "")]
                for r in results
            ],
        )
        print_abuse_info("ADCSESC4", results, extract_domain(results, domain))

    return result_count
