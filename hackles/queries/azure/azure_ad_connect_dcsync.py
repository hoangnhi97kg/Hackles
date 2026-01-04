"""AAD Connect with DCSync"""

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
    name="AAD Connect with DCSync",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.CRITICAL,
)
def get_azure_ad_connect_dcsync(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Azure AD Connect accounts with DCSync rights"""
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[r:GetChanges|GetChangesAll|DCSync]->(d:Domain)
    WHERE n.name =~ '(?i).*(MSOL_|AAD_|SYNC_|AZUREADSSOACC).*'
    {domain_filter}
    RETURN DISTINCT
        n.name AS name,
        CASE WHEN n:User THEN 'User' WHEN n:Computer THEN 'Computer' ELSE 'Other' END AS type,
        type(r) AS permission,
        d.name AS target_domain
    ORDER BY n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AAD Connect with DCSync", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Azure AD account(s) with DCSync rights")

    if results:
        print_warning("[!] CRITICAL: Compromise AAD Connect server to extract creds and DCSync!")
        print_table(
            ["Account", "Type", "Permission", "Target Domain"],
            [[r["name"], r["type"], r["permission"], r["target_domain"]] for r in results],
        )
        print_abuse_info("AzureADConnect", results, extract_domain(results, domain))

    return result_count
