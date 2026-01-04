"""Service Accounts Unprotected"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Service Accounts Unprotected",
    category="Security Hygiene",
    default=True,
    severity=Severity.MEDIUM,
)
def get_service_accounts_unprotected(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Service accounts NOT in Protected Users group"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User {{hasspn: true, enabled: true}})
    WHERE NOT u.name STARTS WITH 'KRBTGT'
      AND NOT EXISTS {{
          MATCH (u)-[:MemberOf*1..]->(g:Group)
          WHERE g.objectid ENDS WITH '-525'
      }}
    {domain_filter}
    RETURN u.name AS service_account, u.description AS description
    ORDER BY u.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Service Accounts Unprotected", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} service account(s) NOT in Protected Users")

    if results:
        print_table(
            ["Service Account", "Description"],
            [[r["service_account"], r["description"]] for r in results],
        )

    return result_count
