"""SQL Servers (SPN Discovery)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="SQL Servers (SPN Discovery)",
    category="Lateral Movement",
    default=True,
    severity=Severity.MEDIUM,
)
def get_sql_servers(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """SQL Servers discovered via SPN enumeration"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE ANY(spn IN c.serviceprincipalnames WHERE toUpper(spn) CONTAINS 'MSSQL')
    {domain_filter}
    RETURN c.name AS computer, c.operatingsystem AS os
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("SQL Servers (SPN Discovery)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} SQL server(s)")

    if results:
        print_table(["Computer", "OS"], [[r["computer"], r["os"]] for r in results])

    return result_count
