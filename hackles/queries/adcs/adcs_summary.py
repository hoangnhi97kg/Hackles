"""ADCS - Certificate Authorities"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS - Certificate Authorities", category="ADCS", default=True, severity=Severity.INFO
)
def get_adcs_summary(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get ADCS summary (Certificate Authorities)"""
    domain_filter = "WHERE toUpper(ca.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (ca:EnterpriseCA)
    {domain_filter}
    RETURN
        ca.name AS name,
        ca.domain AS domain,
        ca.caname AS caname
    ORDER BY ca.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS - Certificate Authorities", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Enterprise CA(s)")

    if results:
        print_table(
            ["Name", "Domain", "CA Name"], [[r["name"], r["domain"], r["caname"]] for r in results]
        )

    return result_count
