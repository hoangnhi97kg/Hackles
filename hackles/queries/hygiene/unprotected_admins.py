"""Unprotected Admins (Not in Protected Users)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Unprotected Admins (Not in Protected Users)",
    category="Security Hygiene",
    default=True,
    severity=Severity.HIGH,
)
def get_unprotected_admins(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Admin accounts NOT in Protected Users group"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{admincount: true, enabled: true}})
    WHERE NOT EXISTS {{
        MATCH (u)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-525'
    }}
    {domain_filter}
    RETURN u.name AS admin, u.description AS description
    ORDER BY u.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Unprotected Admin Accounts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} admin(s) NOT in Protected Users")

    if results:
        print_warning("[!] Protected Users provides extra credential protection!")
        print_table(
            ["Unprotected Admin", "Description"], [[r["admin"], r["description"]] for r in results]
        )

    return result_count
