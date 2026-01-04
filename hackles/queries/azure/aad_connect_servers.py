"""AAD Connect Servers"""

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
    name="AAD Connect Servers", category="Azure/Hybrid", default=True, severity=Severity.HIGH
)
def get_aad_connect_servers(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Azure AD Connect servers (hybrid infrastructure)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE c.name =~ '(?i).*AAD.*CONNECT.*|.*AZURE.*AD.*|.*AADC.*'
       OR ANY(spn IN COALESCE(c.serviceprincipalnames, []) WHERE toUpper(spn) CONTAINS 'AZUREADSSOACC')
    {domain_filter}
    RETURN c.name AS server, c.operatingsystem AS os
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Azure AD Connect Servers", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} potential AAD Connect server(s)")

    if results:
        print_warning("[!] AAD Connect servers sync credentials - high value targets!")
        print_table(["Server", "OS"], [[r["server"], r["os"]] for r in results])
        print_abuse_info("AADConnect", results, extract_domain(results, domain))

    return result_count
