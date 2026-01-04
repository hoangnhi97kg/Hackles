"""Never Changed Password (Active)"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Never Changed Password (Active)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.MEDIUM,
)
def get_never_changed_password(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Active users who never changed their password"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{enabled: true}})
    WHERE (u.pwdlastset = u.whencreated OR u.pwdlastset = 0 OR u.pwdlastset IS NULL)
      AND u.lastlogon > (datetime().epochSeconds - (30 * 86400))
    {domain_filter}
    RETURN u.name AS user, u.whencreated AS created, u.lastlogon AS lastlogon
    ORDER BY u.whencreated ASC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Never Changed Password (Active)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} active user(s) who never changed password")

    if results:
        print_warning("[!] These accounts may use default/initial passwords!")

        def format_date(ts):
            if ts and ts > 0:
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            return "Unknown"

        print_table(
            ["User", "Created", "Last Logon"],
            [[r["user"], format_date(r["created"]), format_date(r["lastlogon"])] for r in results],
        )

    return result_count
