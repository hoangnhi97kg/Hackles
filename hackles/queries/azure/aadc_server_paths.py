"""Attack paths to Azure AD Connect servers from owned principals."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Paths to AAD Connect Servers",
    category="Azure/Hybrid",
    default=False,
    severity=Severity.CRITICAL,
)
def get_aadc_server_paths(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find attack paths from owned principals to Azure AD Connect servers.

    AAD Connect servers store credentials for the MSOL sync account which
    has DCSync rights. Compromising these servers leads to domain compromise.
    """
    domain_filter = "AND toUpper(aadc.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # First find AADC servers
    aadc_query = f"""
    MATCH (aadc:Computer)
    WHERE aadc.name =~ '(?i).*(AADC|AZUREAD|AADCONNECT|DIRSYNC).*'
    OR ANY(spn IN COALESCE(aadc.serviceprincipalnames, [])
           WHERE spn =~ '(?i).*(AADConnect|AzureAD).*')
    {domain_filter}
    RETURN aadc.name AS server
    LIMIT 10
    """
    aadc_results = bh.run_query(aadc_query, params)

    if not aadc_results:
        if not print_header("Paths to AAD Connect Servers", severity, 0):
            return 0
        return 0

    # Then find paths from owned to AADC
    path_query = f"""
    MATCH (owned)
    WHERE (owned:Tag_Owned OR 'owned' IN COALESCE(owned.system_tags, []) OR owned.owned = true)
    MATCH (aadc:Computer)
    WHERE aadc.name =~ '(?i).*(AADC|AZUREAD|AADCONNECT|DIRSYNC).*'
    {domain_filter}
    MATCH p=shortestPath((owned)-[*1..6]->(aadc))
    RETURN owned.name AS owned_principal,
           length(p) AS path_length,
           aadc.name AS aadc_server
    ORDER BY path_length
    LIMIT 20
    """
    results = bh.run_query(path_query, params)
    result_count = len(results)

    if not print_header("Paths to AAD Connect Servers", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} path(s) to AAD Connect server(s)")

    if results:
        print_warning("[!] CRITICAL: Path to AAD Connect = Path to DCSync!")
        print_warning("    Compromise AADC -> Extract MSOL creds -> DCSync entire domain")
        print_table(
            ["Owned Principal", "Hops", "AADC Server"],
            [[r["owned_principal"], r["path_length"], r["aadc_server"]] for r in results],
        )

    return result_count
