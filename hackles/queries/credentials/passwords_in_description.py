"""Passwords in Description"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Passwords in Description",
    category="Privilege Escalation",
    default=True,
    severity=Severity.LOW,
)
def get_passwords_in_description(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find users with passwords potentially stored in description field"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    WHERE u.enabled = true
    AND u.description IS NOT NULL
    AND (toLower(u.description) CONTAINS 'pass' OR toLower(u.description) CONTAINS 'pwd' OR toLower(u.description) CONTAINS 'cred')
    {domain_filter}
    RETURN u.name AS name, u.description AS description, u.admincount AS admin
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Passwords in Description", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} user(s) with potential passwords in description")

    if results:
        print_warning("Review these descriptions manually for exposed credentials!")
        print_table(
            ["Name", "Description", "Admin"],
            [
                [
                    r["name"],
                    (
                        r["description"][:80] + "..."
                        if r["description"] and len(r["description"]) > 80
                        else r["description"]
                    ),
                    r["admin"],
                ]
                for r in results
            ],
        )

    return result_count
