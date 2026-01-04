"""Computer-to-Computer Admin Chains"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Computer Admin Chains",
    category="Lateral Movement",
    default=True,
    severity=Severity.MEDIUM,
)
def get_computer_admin_chains(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find computers where local admins can chain to other computers (lateral movement paths)"""
    domain_filter = "AND toUpper(c1.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c1:Computer)<-[:AdminTo]-(u:User)-[:AdminTo]->(c2:Computer)
    WHERE c1 <> c2
    AND c1.enabled = true AND c2.enabled = true
    {domain_filter}
    WITH u, collect(DISTINCT c1.name) + collect(DISTINCT c2.name) AS computers
    WITH u, size(computers) AS computer_count, computers[0..5] AS sample_computers
    WHERE computer_count > 1
    RETURN u.name AS user, u.enabled AS enabled, computer_count AS computers_admin_to, sample_computers
    ORDER BY computer_count DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Computer Admin Chains", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} user(s) who can chain between computers")

    if results:
        print_warning("[!] These users can move laterally between multiple computers")
        print_warning("    Compromising one grants access to others via credential reuse")

        # Stats
        total_reach = sum(r["computers_admin_to"] for r in results)
        max_reach = max(r["computers_admin_to"] for r in results)
        print_warning(
            f"    Total: {result_count} users can reach {total_reach} computer relationships"
        )
        print_warning(f"    Highest reach: {max_reach} computers from single user")

        print_table(
            ["User", "Enabled", "Count", "Sample Computers"],
            [
                [r["user"], r["enabled"], r["computers_admin_to"], r["sample_computers"]]
                for r in results
            ],
        )

    return result_count
