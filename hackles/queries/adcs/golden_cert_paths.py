"""Golden Certificate Paths"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Golden Certificate Paths", category="ADCS", default=True, severity=Severity.CRITICAL
)
def get_golden_cert_paths(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Golden Certificate attack paths (CA compromise)"""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(c:Computer)-[:GoldenCert]->(d:Domain)
    {domain_filter}
    RETURN c.name AS ca_host, d.name AS domain
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Golden Certificate Paths", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Golden Certificate path(s)")

    if results:
        print_warning("Compromising CA host allows forging certificates for ANY user!")
        print_table(["CA Host", "Domain"], [[r["ca_host"], r["domain"]] for r in results])
        print_abuse_info("GoldenCert", results, domain)

    return result_count
