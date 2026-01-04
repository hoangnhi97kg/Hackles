"""LDAP Signing Disabled (DCs)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="LDAP Signing Disabled (DCs)",
    category="Security Hygiene",
    default=True,
    severity=Severity.MEDIUM,
)
def get_ldap_signing_disabled(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Domain Controllers with LDAP signing disabled"""
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:DCFor]->(d:Domain)
    WHERE c.ldapsigning = false OR c.ldapsepa = false
    {domain_filter}
    RETURN c.name AS dc, c.ldapsigning AS ldap_signing, c.ldapsepa AS ldaps_epa, d.name AS domain
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("LDAP Signing Disabled (Domain Controllers)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} DC(s) with LDAP signing issues")

    if results:
        print_warning("DCs without LDAP signing/EPA are vulnerable to relay attacks!")
        print_table(
            ["Domain Controller", "LDAP Signing", "LDAPS EPA", "Domain"],
            [[r["dc"], r["ldap_signing"], r["ldaps_epa"], r["domain"]] for r in results],
        )

    return result_count
