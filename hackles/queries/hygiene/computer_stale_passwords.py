"""Computer Stale Passwords (90d+)"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.core.config import config
from datetime import datetime
import time


if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="Computer Stale Passwords (90d+)",
    category="Security Hygiene",
    default=False,
    severity=Severity.LOW
)
def get_computer_stale_passwords(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Computer accounts with stale passwords (configurable threshold)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer {{enabled: true}})
    WHERE c.pwdlastset < (datetime().epochseconds - ({config.stale_days} * 86400))
      AND c.pwdlastset > 0
    {domain_filter}
    RETURN c.name AS computer, c.pwdlastset AS pwdlastset
    ORDER BY c.pwdlastset ASC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header(f"Computer Stale Passwords ({config.stale_days}+ days)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with stale passwords")

    if results:
        def format_age(ts):
            if ts and ts > 0:
                days = int((datetime.now().timestamp() - ts) / 86400)
                return f"{days} days"
            return "Unknown"

        print_table(
            ["Computer", "Password Age"],
            [[r["computer"], format_age(r["pwdlastset"])] for r in results]
        )

    return result_count
