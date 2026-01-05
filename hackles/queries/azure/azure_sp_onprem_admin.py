"""Service principals with on-premises admin rights."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Service Accounts with On-Prem Admin",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.HIGH,
)
def get_azure_sp_onprem_admin(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find service accounts/principals with local admin rights on computers.

    Service accounts with AdminTo rights on computers are high-value targets.
    Compromising the service or its credentials grants access to those systems.
    """
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (sp)-[:AdminTo]->(c:Computer)
    WHERE sp.serviceprincipalnames IS NOT NULL
    AND size(sp.serviceprincipalnames) > 0
    {domain_filter}
    RETURN DISTINCT
        sp.name AS service_account,
        {node_type("sp")} AS type,
        count(c) AS admin_count
    ORDER BY admin_count DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Service Accounts with On-Prem Admin", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} service account(s) with admin rights")

    if results:
        print_warning("[!] Service accounts with local admin = high-value Kerberoast targets!")
        print_table(
            ["Service Account", "Type", "Admin On # Computers"],
            [[r["service_account"], r["type"], r["admin_count"]] for r in results],
        )

    return result_count
