"""SID History Abuse"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="SID History Abuse", category="Privilege Escalation", default=True, severity=Severity.HIGH
)
def get_sid_history(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find objects with SID history for privilege escalation"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:HasSIDHistory]->(target)
    {domain_filter.replace('AND', 'WHERE') if domain_filter else ''}
    RETURN n.name AS principal, {node_type('n')} AS type, target.name AS sid_history_of, {node_type('target')} AS target_type
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("SID History Abuse", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} SID history relationship(s)")

    if results:
        print_table(
            ["Principal", "Type", "Has SID History Of", "Target Type"],
            [[r["principal"], r["type"], r["sid_history_of"], r["target_type"]] for r in results],
        )
        print_abuse_info("HasSIDHistory", results, domain)

    return result_count


# ============================================================================
# NEW QUERIES - Remote Access
# ============================================================================
