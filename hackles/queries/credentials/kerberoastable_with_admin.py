"""Kerberoastable (With Admin Rights)"""

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
    name="Kerberoastable (With Admin Rights)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_kerberoastable_with_admin(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Kerberoastable users with local admin rights - immediate impact upon crack"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{hasspn: true, enabled: true}})
    WHERE NOT u.name STARTS WITH 'KRBTGT'
    {domain_filter}
    OPTIONAL MATCH (u)-[:AdminTo]->(c1:Computer)
    OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)-[:AdminTo]->(c2:Computer)
    WITH u, COLLECT(DISTINCT c1) + COLLECT(DISTINCT c2) AS computers
    WHERE SIZE(computers) > 0
    RETURN u.name AS name, SIZE(computers) AS admin_count, u.description AS description, u.serviceprincipalnames AS spns
    ORDER BY admin_count DESC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Kerberoastable (With Admin Rights)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Kerberoastable user(s) with admin rights")

    if results:
        print_warning("[!] Cracking these accounts gives immediate local admin access!")
        print_table(
            ["Name", "Admin To (Count)", "SPN"],
            [[r["name"], r["admin_count"], r["spns"]] for r in results],
        )
        print_abuse_info("Kerberoasting", results, extract_domain(results, domain))

    return result_count
