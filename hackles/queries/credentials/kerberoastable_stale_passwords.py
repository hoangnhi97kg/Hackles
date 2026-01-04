"""Kerberoastable (Stale Passwords 5yr+)"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Kerberoastable (Stale Passwords 5yr+)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_kerberoastable_stale_passwords(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Kerberoastable users with passwords older than 5 years - most likely to crack"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{hasspn: true, enabled: true}})
    WHERE u.pwdlastset < (datetime().epochSeconds - (1825 * 86400))
      AND NOT u.pwdlastset IN [-1.0, 0.0]
      AND NOT u.name STARTS WITH 'KRBTGT'
      {domain_filter}
    RETURN u.name AS name,
           u.pwdlastset AS pwdlastset,
           u.description AS description,
           u.admincount AS admincount,
           u.serviceprincipalnames AS spns
    ORDER BY u.pwdlastset ASC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Kerberoastable (Stale Passwords 5+ Years)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Kerberoastable user(s) with stale passwords")

    if results:
        print_warning("[!] Old passwords are significantly more likely to be crackable!")
        admin_count = sum(1 for r in results if r.get("admincount"))
        if admin_count:
            print_warning(f"[!] {admin_count} are admin accounts!")

        def format_pwd_age(ts):
            if ts and ts > 0:
                days = int((datetime.now().timestamp() - ts) / 86400)
                return f"{days // 365}y {(days % 365) // 30}m"
            return "Unknown"

        print_table(
            ["Name", "Password Age", "Admin", "SPN"],
            [
                [r["name"], format_pwd_age(r["pwdlastset"]), r["admincount"], r["spns"]]
                for r in results
            ],
        )
        print_abuse_info("Kerberoasting", results, extract_domain(results, domain))

    return result_count
