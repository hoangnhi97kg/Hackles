"""Azure AD SSO Account (AZUREADSSOACC) Detection"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Azure AD SSO Account", category="Basic Info", default=True, severity=Severity.HIGH
)
def get_azuread_sso(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find AZUREADSSOACC accounts (Azure Seamless SSO - high value target)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE c.name STARTS WITH 'AZUREADSSOACC'
    OR toLower(c.name) CONTAINS 'azureadssoacc'
    {domain_filter}
    RETURN c.name AS computer, c.domain AS domain,
           c.enabled AS enabled, c.operatingsystem AS os,
           c.lastlogontimestamp AS last_logon,
           c.hasspn AS has_spn
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Azure AD SSO Account (AZUREADSSOACC)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} AZUREADSSOACC account(s)")

    if results:
        print_warning("[!] AZUREADSSOACC is used for Azure AD Seamless SSO!")
        print_warning(
            "    This account's password hash can forge Kerberos tickets for ANY Azure AD user."
        )
        print()
        print("    Attack vector:")
        print("    1. Extract NTLM hash of AZUREADSSOACC$ from AD")
        print("    2. Forge Kerberos tickets for cloud users")
        print("    3. Access Azure/M365 resources as any synced user")
        print()
        print("    Detection: Monitor for unusual ticket requests against this account")
        print()

        print_table(
            ["Computer", "Domain", "Enabled", "Has SPN"],
            [[r["computer"], r["domain"], r["enabled"], r["has_spn"]] for r in results],
        )

    return result_count
