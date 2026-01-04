"""Delegatable Admins (Not Sensitive)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Delegatable Admins (Not Sensitive)",
    category="Delegation",
    default=True,
    severity=Severity.HIGH,
)
def get_delegatable_admins(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Admin accounts without 'Account is sensitive' flag (can be delegated)"""
    domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{sensitive: false, admincount: true, enabled: true}})
    {domain_filter}
    RETURN u.name AS delegatable_admin, u.description AS description
    ORDER BY u.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Delegatable Admin Accounts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} admin account(s) that can be delegated")

    if results:
        print_warning("[!] These admins lack 'Account is sensitive and cannot be delegated'!")
        print_table(
            ["Delegatable Admin", "Description"],
            [[r["delegatable_admin"], r["description"]] for r in results],
        )

    return result_count
