"""Users Never Logged In"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Users Never Logged In", category="Security Hygiene", default=True, severity=Severity.LOW
)
def get_users_never_logged_in(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find enabled users who have never logged in"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    WHERE u.enabled = true
    AND (u.lastlogon IS NULL OR u.lastlogon = 0 OR u.lastlogon = -1)
    AND (u.lastlogontimestamp IS NULL OR u.lastlogontimestamp = 0 OR u.lastlogontimestamp = -1)
    {domain_filter}
    RETURN u.name AS name, u.displayname AS display_name, u.admincount AS admin, u.pwdlastset AS pwd_last_set
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Users Never Logged In", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} user(s) who never logged in")

    if results:
        print_warning("Review these accounts - they may be stale or unused")
        print_table(
            ["Name", "Display Name", "Admin", "Password Set"],
            [[r["name"], r["display_name"], r["admin"], r["pwd_last_set"]] for r in results],
        )

    return result_count


# ============================================================================
# NEW QUERIES - Attack Paths
# ============================================================================
