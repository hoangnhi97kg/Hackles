"""gMSA Password Readers"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_for_query
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="gMSA Password Readers",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
)
def get_gmsa_readers(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get principals with gMSA password read rights"""
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:ReadGMSAPassword]->(g)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    {domain_filter}
    RETURN n.name AS principal, {node_type("n")} AS type, g.name AS gmsa_account
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("gMSA Password Readers", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} gMSA reader(s)")

    if results:
        print_table(
            ["Principal", "Type", "gMSA Account"],
            [[r["principal"], r["type"], r["gmsa_account"]] for r in results],
        )
        print_abuse_for_query("gmsa", results, target_key="gmsa_account")

    return result_count
