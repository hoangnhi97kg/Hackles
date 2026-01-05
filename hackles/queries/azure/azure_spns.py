"""Azure-related service principal names on computers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Azure-Related SPNs",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.MEDIUM,
)
def get_azure_spns(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find computers with Azure-related service principal names.

    Identifies systems hosting Azure services (AAD Connect, Azure AD,
    ADFS, etc.) which are high-value targets for hybrid attacks.
    """
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE c.serviceprincipalnames IS NOT NULL
    AND ANY(spn IN c.serviceprincipalnames
            WHERE spn =~ '(?i).*(azure|aad|adfs|federation|sts|oauth|oidc).*')
    {domain_filter}
    RETURN c.name AS computer,
           c.operatingsystem AS os,
           [spn IN c.serviceprincipalnames
            WHERE spn =~ '(?i).*(azure|aad|adfs|federation|sts|oauth|oidc).*'][0..3] AS azure_spns
    ORDER BY c.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Azure-Related SPNs", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} computer(s) with Azure-related SPNs")

    if results:
        print_warning("[*] These systems host Azure/federation services - high-value targets")
        print_table(
            ["Computer", "OS", "Azure SPNs"],
            [
                [r["computer"], r.get("os") or "N/A", ", ".join(r.get("azure_spns") or [])]
                for r in results
            ],
        )

    return result_count
