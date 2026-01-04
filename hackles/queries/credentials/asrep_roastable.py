"""AS-REP Roastable Users"""

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
    name="AS-REP Roastable Users",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
)
def get_asrep_roastable(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get AS-REP roastable users (dontreqpreauth=true)"""
    domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{dontreqpreauth: true}})
    {domain_filter}
    RETURN
        u.name AS name,
        u.displayname AS displayname,
        u.enabled AS enabled,
        u.admincount AS admincount,
        u.description AS description
    ORDER BY u.admincount DESC, u.name
    LIMIT 1000
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AS-REP Roastable Users (Pre-Auth Disabled)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} AS-REP roastable user(s)")

    if results:
        admin_count = sum(1 for r in results if r.get("admincount"))
        if admin_count:
            print_warning(f"[!] {admin_count} are admin accounts!")

        print_table(
            ["Name", "Display Name", "Enabled", "Admin", "Description"],
            [
                [r["name"], r["displayname"], r["enabled"], r["admincount"], r["description"]]
                for r in results
            ],
        )
        print_abuse_info("ASREPRoasting", results, extract_domain(results, domain))

    return result_count
