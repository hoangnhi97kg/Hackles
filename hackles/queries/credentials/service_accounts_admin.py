"""Service Accounts with Admin Rights"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Service Accounts with Admin Rights",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
)
def get_service_accounts_admin(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find service accounts with local admin rights on computers.

    Service accounts with admin rights are high-value targets - if compromised,
    attackers can pivot to multiple machines.
    """
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Service accounts typically have SPN set (hasspn=true)
    query = f"""
    MATCH (u:User {{hasspn: true}})-[:AdminTo|MemberOf*1..3]->(c:Computer)
    WHERE u.enabled = true
    AND NOT u.name STARTS WITH 'KRBTGT'
    {domain_filter}
    WITH u, collect(DISTINCT c.name) AS computers, count(DISTINCT c) AS computer_count
    RETURN
        u.name AS service_account,
        u.displayname AS display_name,
        CASE WHEN size(u.serviceprincipalnames) > 0 THEN u.serviceprincipalnames[0] ELSE null END AS primary_spn,
        computer_count,
        CASE
            WHEN computer_count > 10 THEN computers[0..10] + ['... +' + toString(computer_count - 10) + ' more']
            ELSE computers
        END AS admin_on_computers
    ORDER BY computer_count DESC
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Service Accounts with Admin Rights", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} service account(s) with admin rights (limit 100)")

    if results:
        # Count high-risk service accounts (admin on many machines)
        high_risk = sum(1 for r in results if r.get("computer_count", 0) >= 5)
        if high_risk:
            print_warning(
                f"[!] {high_risk} service account(s) are admin on 5+ computers - high blast radius!"
            )

        print_table(
            ["Service Account", "Display Name", "Primary SPN", "# Computers", "Admin On"],
            [
                [
                    r["service_account"],
                    r.get("display_name", ""),
                    r.get("primary_spn", ""),
                    r["computer_count"],
                    ", ".join(r.get("admin_on_computers", [])[:5]),
                ]
                for r in results
            ],
        )

    return result_count
