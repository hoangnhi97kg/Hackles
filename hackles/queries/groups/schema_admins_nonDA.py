"""Schema/Enterprise Admins (Non-DA)"""

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
    name="Schema/Enterprise Admins (Non-DA)",
    category="Dangerous Groups",
    default=True,
    severity=Severity.CRITICAL,
)
def get_schema_admins_nonDA(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Schema/Enterprise Admins who aren't Domain Admins (forest-level privileges)"""
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (m)-[:MemberOf*1..]->(g:Group)
    WHERE (g.objectid ENDS WITH '-518' OR g.objectid ENDS WITH '-519')
    AND (m:User OR m:Computer)
    AND NOT EXISTS {{
        MATCH (m)-[:MemberOf*1..]->(da:Group)
        WHERE da.objectid ENDS WITH '-512'
    }}
    {domain_filter}
    RETURN DISTINCT
        m.name AS member,
        CASE WHEN m:User THEN 'User' WHEN m:Computer THEN 'Computer' ELSE 'Other' END AS member_type,
        g.name AS high_priv_group,
        m.enabled AS enabled
    ORDER BY m.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Schema/Enterprise Admins (Non-DA)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Schema/Enterprise Admin(s) not in Domain Admins")

    if results:
        print_warning("[!] These accounts have FOREST-LEVEL privileges but may be overlooked!")
        print_table(
            ["Member", "Type", "High Priv Group", "Enabled"],
            [[r["member"], r["member_type"], r["high_priv_group"], r["enabled"]] for r in results],
        )
        print_abuse_info("SchemaAdmin", results, extract_domain(results, domain))

    return result_count
