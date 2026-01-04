"""Stale Accounts (90+ days)"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Stale Accounts (90+ days)",
    category="Security Hygiene",
    default=True,
    severity=Severity.LOW,
)
def get_stale_accounts(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get stale user accounts (no login in configured threshold days)"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Calculate threshold days ago in epoch
    import time

    threshold_days_ago = int(time.time()) - (config.stale_days * 24 * 60 * 60)

    query = f"""
    MATCH (u:User)
    WHERE u.enabled = true
    AND u.lastlogon < $cutoff
    AND u.lastlogon > 0
    {domain_filter}
    RETURN
        u.name AS name,
        u.displayname AS displayname,
        u.admincount AS admincount,
        u.lastlogon AS lastlogon,
        u.pwdlastset AS pwdlastset
    ORDER BY u.lastlogon
    LIMIT 50
    """
    params["cutoff"] = threshold_days_ago
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header(f"Stale User Accounts ({config.stale_days}+ days)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} stale account(s) (limit 50)")

    if results:
        # Convert epoch to readable dates
        def epoch_to_date(epoch):
            if epoch and epoch > 0:
                try:
                    return time.strftime("%Y-%m-%d", time.localtime(epoch))
                except:
                    return "Unknown"
            return "Never"

        print_table(
            ["User", "Display Name", "Admin", "Last Login", "Pwd Last Set"],
            [
                [
                    r["name"],
                    r["displayname"],
                    r["admincount"],
                    epoch_to_date(r["lastlogon"]),
                    epoch_to_date(r["pwdlastset"]),
                ]
                for r in results
            ],
        )

    return result_count
