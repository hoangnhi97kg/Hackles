"""Enabled Guest Accounts"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Enabled Guest Accounts", category="Security Hygiene", default=True, severity=Severity.HIGH
)
def get_enabled_guest_accounts(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find enabled Guest accounts"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    WHERE u.objectid ENDS WITH '-501'
    AND u.enabled = true
    {domain_filter}
    RETURN u.name AS account, u.domain AS domain, u.lastlogon AS last_logon
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Enabled Guest Accounts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} enabled Guest account(s)")

    if results:
        print_warning("Enabled Guest accounts are a security risk!")
        print_table(
            ["Account", "Domain", "Last Logon"],
            [[r["account"], r["domain"], r["last_logon"]] for r in results],
        )

    return result_count
