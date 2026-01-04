"""KRBTGT Password Age"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="KRBTGT Password Age", category="Security Hygiene", default=True, severity=Severity.MEDIUM
)
def get_krbtgt_age(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """KRBTGT account password age"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    WHERE u.name STARTS WITH 'KRBTGT'
    {domain_filter}
    RETURN u.name AS krbtgt, u.pwdlastset AS pwdlastset
    ORDER BY u.pwdlastset ASC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("KRBTGT Password Age", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} KRBTGT account(s)")

    if results:

        def format_age(ts):
            if ts and ts > 0:
                days = int((datetime.now().timestamp() - ts) / 86400)
                return f"{days} days ({days // 365}y {(days % 365) // 30}m)"
            return "Unknown"

        old_count = sum(
            1
            for r in results
            if r.get("pwdlastset")
            and (datetime.now().timestamp() - r["pwdlastset"]) > (180 * 86400)
        )
        if old_count:
            print_warning(f"[!] {old_count} KRBTGT account(s) not rotated in 180+ days!")

        print_table(
            ["KRBTGT", "Password Age"],
            [[r["krbtgt"], format_age(r["pwdlastset"])] for r in results],
        )

    return result_count
