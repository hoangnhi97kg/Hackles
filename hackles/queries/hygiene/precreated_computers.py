"""Pre-Created Computer Accounts"""

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
    name="Pre-Created Computer Accounts",
    category="Security Hygiene",
    default=True,
    severity=Severity.HIGH,
)
def get_precreated_computers(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find pre-created computer accounts (may have guessable passwords)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE c.enabled = true
    AND (c.haslaps IS NULL OR c.haslaps = false)
    AND (c.lastlogon IS NULL OR c.lastlogon = 0 OR c.lastlogon = -1)
    {domain_filter}
    RETURN
        c.name AS computer,
        c.operatingsystem AS os,
        c.haslaps AS has_laps,
        c.description AS description
    ORDER BY c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Pre-Created Computer Accounts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} potentially pre-created computer account(s)")

    if results:
        print_warning(
            "[!] Pre-created computer accounts may have password = lowercase computer name!"
        )
        print_warning("[!] Try: lowercase hostname without $ (e.g., 'workstation01')")
        print_table(
            ["Computer", "OS", "Has LAPS", "Description"],
            [[r["computer"], r["os"], r["has_laps"], r["description"]] for r in results],
        )
        print_abuse_info("PreCreatedComputer", results, extract_domain(results, domain))

    return result_count
