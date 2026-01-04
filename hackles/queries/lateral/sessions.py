"""Active Sessions (Admins)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Active Sessions (Admins)",
    category="Lateral Movement",
    default=True,
    severity=Severity.MEDIUM,
)
def get_sessions(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Get active sessions - where are privileged users logged in"""
    domain_filter = "WHERE toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{admincount: true}})-[:HasSession]->(c:Computer)
    {domain_filter}
    RETURN
        u.name AS user,
        c.name AS computer,
        c.operatingsystem AS os
    ORDER BY u.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Active Sessions (High-Value Users)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} session(s) of admin users (limit 50)")

    if results:
        print_warning("[!] Admin users logged in - potential credential harvesting targets!")
        print_table(
            ["Admin User", "Logged Into", "OS"],
            [[r["user"], r["computer"], r["os"]] for r in results],
        )

    return result_count
