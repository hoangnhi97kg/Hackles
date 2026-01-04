"""Users with Paths to Domain Admin"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Users with Paths to DA", category="Security Hygiene", default=True, severity=Severity.HIGH
)
def get_users_path_to_da(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Calculate percentage and list of users with attack paths to Domain Admins"""
    domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # First get total enabled users
    total_query = f"""
    MATCH (u:User)
    {domain_filter}
    {"AND" if domain_filter else "WHERE"} u.enabled = true
    RETURN count(u) AS total_users
    """
    total_result = bh.run_query(total_query, params)
    total_users = total_result[0]["total_users"] if total_result else 0

    # Now find users with paths to DA
    query = f"""
    MATCH (u:User)
    {domain_filter}
    {"AND" if domain_filter else "WHERE"} u.enabled = true
    MATCH (g:Group)
    WHERE g.objectid ENDS WITH '-512'
    MATCH p=shortestPath((u)-[*1..8]->(g))
    WITH u, min(length(p)) AS path_length
    RETURN u.name AS user, u.domain AS domain,
           u.admincount AS is_admin, path_length AS hops_to_da
    ORDER BY path_length ASC
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Users with Paths to Domain Admin", severity, result_count):
        return result_count

    if total_users > 0:
        percentage = (result_count / total_users) * 100
        print_subheader(
            f"{result_count} of {total_users} users ({percentage:.1f}%) have paths to DA"
        )
    else:
        print_subheader(f"Found {result_count} user(s) with paths to DA")

    if results:
        if total_users > 0:
            percentage = (result_count / total_users) * 100
            if percentage > 10:
                print_warning(f"[!] HIGH RISK: {percentage:.1f}% of users can reach Domain Admin!")
            elif percentage > 5:
                print_warning(f"[!] MODERATE: {percentage:.1f}% of users have paths to DA")
            else:
                print(f"    LOW: Only {percentage:.1f}% of users have paths to DA")
        print()

        # Non-admin users with paths are more concerning
        non_admins_with_path = sum(1 for r in results if not r["is_admin"])
        print_warning(f"    {non_admins_with_path} non-admin users have paths to DA")

        # Short paths are critical
        short_paths = sum(1 for r in results if r["hops_to_da"] <= 3)
        print_warning(f"    {short_paths} users are within 3 hops of DA")

        print_table(
            ["User", "Domain", "Admin Flag", "Hops to DA"],
            [[r["user"], r["domain"], r["is_admin"], r["hops_to_da"]] for r in results],
        )

    return result_count
