"""Azure AD Connect Accounts"""

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
    name="Azure AD Connect Accounts",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.CRITICAL,
)
def get_azure_ad_connect_accounts(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Azure AD Connect / MSOL / AAD Sync accounts"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)
    WHERE (n:User OR n:Computer)
    AND (n.name =~ '(?i).*MSOL_.*' OR n.name =~ '(?i).*AAD_.*' OR n.name =~ '(?i).*SYNC_.*' OR n.name =~ '(?i).*AZUREADSSOACC.*')
    {domain_filter}
    RETURN
        n.name AS name,
        CASE WHEN n:User THEN 'User' WHEN n:Computer THEN 'Computer' ELSE 'Other' END AS type,
        n.enabled AS enabled,
        n.admincount AS admincount,
        n.description AS description
    ORDER BY n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Azure AD Connect Accounts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Azure AD Connect / MSOL / Sync account(s)")

    if results:
        print_warning("[!] These accounts often have DCSync rights - HIGH VALUE TARGETS!")
        print_table(
            ["Name", "Type", "Enabled", "Admin", "Description"],
            [
                [r["name"], r["type"], r["enabled"], r["admincount"], r["description"]]
                for r in results
            ],
        )
        print_abuse_info("AzureADConnect", results, extract_domain(results, domain))

    return result_count
