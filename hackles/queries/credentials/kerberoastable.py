"""Kerberoastable Users"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Kerberoastable Users",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH
)
def get_kerberoastable(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Get Kerberoastable users (hasspn=true)"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{hasspn: true}})
    WHERE NOT u.name STARTS WITH 'KRBTGT'
    {domain_filter}
    RETURN
        u.name AS name,
        u.displayname AS displayname,
        u.enabled AS enabled,
        u.admincount AS admincount,
        u.description AS description,
        u.serviceprincipalnames AS spns,
        u.pwdlastset AS pwdlastset,
        CASE
            WHEN u.pwdlastset IS NULL THEN 'Unknown'
            WHEN u.pwdlastset = 0 THEN 'Never'
            WHEN (datetime().epochSeconds - u.pwdlastset) > 31536000 THEN '>1 year'
            WHEN (datetime().epochSeconds - u.pwdlastset) > 15552000 THEN '>6 months'
            WHEN (datetime().epochSeconds - u.pwdlastset) > 7776000 THEN '>3 months'
            WHEN (datetime().epochSeconds - u.pwdlastset) > 2592000 THEN '>1 month'
            ELSE '<1 month'
        END AS pwd_age
    ORDER BY u.admincount DESC, u.pwdlastset ASC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Kerberoastable Users (SPN Set)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Kerberoastable user(s)")

    if results:
        # Highlight admin accounts and old passwords
        admin_count = sum(1 for r in results if r.get("admincount"))
        old_pwd_count = sum(1 for r in results if r.get("pwd_age") in ['>1 year', '>6 months'])
        if admin_count:
            print_warning(f"[!] {admin_count} are admin accounts!")
        if old_pwd_count:
            print_warning(f"[!] {old_pwd_count} have passwords older than 6 months (easier to crack)")

        print_table(
            ["Name", "Display Name", "Enabled", "Admin", "Pwd Age", "SPN"],
            [[r["name"], r["displayname"], r["enabled"], r["admincount"],
              r.get("pwd_age", "Unknown"), r["spns"]] for r in results]
        )
        print_abuse_info("Kerberoasting", results, extract_domain(results, domain))

    return result_count
