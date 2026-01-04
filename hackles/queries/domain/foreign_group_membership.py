"""Foreign Group Membership"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Foreign Group Membership", category="Basic Info", default=True, severity=Severity.INFO
)
def get_foreign_group_membership(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get users from foreign domains in local groups"""
    query = """
    MATCH (u)-[:MemberOf]->(g:Group)
    WHERE u.domain <> g.domain
    RETURN
        u.name AS user,
        u.domain AS user_domain,
        g.name AS group_name,
        g.domain AS group_domain
    ORDER BY g.domain, g.name
    LIMIT 50
    """
    results = bh.run_query(query)
    result_count = len(results)

    if not print_header("Foreign Group Membership", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} foreign group membership(s) (limit 50)")

    if results:
        print_warning("[!] Cross-domain memberships can be leveraged for lateral movement!")
        print_table(
            ["User", "User Domain", "Member Of", "Group Domain"],
            [[r["user"], r["user_domain"], r["group_name"], r["group_domain"]] for r in results],
        )

    return result_count
