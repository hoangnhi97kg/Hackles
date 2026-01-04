"""LAPS Password Readers"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="LAPS Password Readers", category="ACL Abuse", default=True, severity=Severity.MEDIUM
)
def get_laps_readers(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get principals that can read LAPS passwords"""
    domain_filter = "WHERE toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer)
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type('n')} AS type,
        c.name AS computer
    ORDER BY n.name, c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("LAPS Password Readers", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} LAPS read permission(s) (limit 100)")

    if results:
        print_table(
            ["Principal", "Type", "Can Read LAPS On"],
            [[r["principal"], r["type"], r["computer"]] for r in results],
        )
        print_abuse_info("ReadLAPSPassword", results, extract_domain(results, domain))

    return result_count
