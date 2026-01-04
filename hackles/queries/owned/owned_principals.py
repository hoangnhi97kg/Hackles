"""Owned Principals"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(name="Owned Principals", category="Owned", default=True, severity=Severity.INFO)
def get_owned_principals(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get all owned principals (BloodHound CE uses system_tags)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    from_owned_filter = "AND toUpper(n.name) = toUpper($from_owned)" if config.from_owned else ""
    params = {}
    if domain:
        params["domain"] = domain
    if config.from_owned:
        params["from_owned"] = config.from_owned

    # Check both system_tags and owned property (BloodHound CE versions differ)
    query = f"""
    MATCH (n)
    WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)
    {domain_filter}
    {from_owned_filter}
    RETURN
        n.name AS name,
        {node_type('n')} AS type,
        n.enabled AS enabled,
        n.description AS description,
        n.admincount AS admin,
        CASE WHEN 'admin_tier_0' IN n.system_tags THEN true ELSE false END AS tier_zero
    ORDER BY {node_type('n')}, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Owned Principals", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} owned principal(s)")

    if results:
        print_table(
            ["Name", "Type", "Enabled", "Admin", "Tier Zero", "Description"],
            [
                [
                    r["name"],
                    r["type"],
                    r.get("enabled", "-"),
                    r.get("admin", "-"),
                    r.get("tier_zero", "-"),
                    r.get("description", "-"),
                ]
                for r in results
            ],
        )

    return result_count
