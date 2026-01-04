"""SQL Admin Access"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="SQL Admin Access", category="Lateral Movement", default=True, severity=Severity.MEDIUM
)
def get_sql_admin(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Get non-admin principals with SQL Server admin access"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:SQLAdmin]->(c:Computer)
    WHERE (n:User OR n:Group)
    AND (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN n.name AS principal, {node_type('n')} AS type, c.name AS sql_server, c.operatingsystem AS os
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("SQL Admin Access", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} SQL admin access path(s)")

    if results:
        print_table(
            ["Principal", "Type", "SQL Server", "OS"],
            [[r["principal"], r["type"], r["sql_server"], r["os"]] for r in results],
        )
        print_abuse_info(
            "SQLAdmin",
            [{"principal": r["principal"], "sql_server": r["sql_server"]} for r in results],
            domain,
        )

    return result_count


# ============================================================================
# NEW QUERIES - Security Hygiene
# ============================================================================
