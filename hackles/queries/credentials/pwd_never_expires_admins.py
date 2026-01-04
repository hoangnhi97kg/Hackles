"""Privileged - Pwd Never Expires"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Privileged - Pwd Never Expires",
    category="Privilege Escalation",
    default=True,
    severity=Severity.MEDIUM,
)
def get_pwd_never_expires_admins(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find privileged accounts with password never expires"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    WHERE u.enabled = true
    AND u.pwdneverexpires = true
    AND u.admincount = true
    {domain_filter}
    RETURN
        u.name AS name,
        u.displayname AS displayname,
        u.pwdlastset AS pwdlastset,
        u.description AS description
    ORDER BY u.pwdlastset ASC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Privileged Accounts - Pwd Never Expires", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} privileged account(s) with non-expiring passwords")

    if results:
        print_table(
            ["Name", "Display Name", "Pwd Last Set", "Description"],
            [[r["name"], r["displayname"], r["pwdlastset"], r["description"]] for r in results],
        )
        print_abuse_info("PasswordNeverExpires", results, extract_domain(results, domain))

    return result_count
