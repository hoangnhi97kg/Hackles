"""GetChangesAll without GetChanges - partial DCSync detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="GetChangesAll Only (Partial DCSync)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
)
def get_getchangesall_only(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find principals with GetChangesAll but not GetChanges.

    While full DCSync requires both GetChanges and GetChangesAll,
    GetChangesAll alone can still replicate some sensitive information.
    This may indicate misconfiguration or an incomplete attack setup.
    """
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:GetChangesAll]->(d:Domain)
    WHERE NOT (n)-[:GetChanges]->(d)
    AND NOT (n)-[:DCSync]->(d)
    AND (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    AND NOT n.name STARTS WITH 'ENTERPRISE DOMAIN CONTROLLERS@'
    AND NOT n.objectid ENDS WITH '-516'
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type("n")} AS type,
        d.name AS domain
    ORDER BY n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("GetChangesAll Only (Partial DCSync)", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} principal(s) with GetChangesAll only")

    if results:
        print_warning("[!] GetChangesAll without GetChanges - unusual configuration!")
        print_warning("    May indicate misconfiguration or partial attack setup")
        print_table(
            ["Principal", "Type", "Domain"],
            [[r["principal"], r["type"], r["domain"]] for r in results],
        )

    return result_count
