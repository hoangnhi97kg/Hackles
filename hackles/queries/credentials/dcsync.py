"""DCSync Privileges (Non-Admin)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="DCSync Privileges (Non-Admin)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_dcsync(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Get non-admin principals with DCSync privileges"""
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Filter out legitimate groups that need DCSync for replication
    query = f"""
    MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.name STARTS WITH 'ENTERPRISE DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@'
    AND NOT n.objectid ENDS WITH '-516'
    AND NOT n.objectid ENDS WITH '-521'
    {domain_filter}
    RETURN DISTINCT
        n.name AS name,
        {node_type('n')} AS type,
        d.name AS domain
    ORDER BY n.name
    LIMIT 1000
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("DCSync Privileges (Non-Admin)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} non-admin principal(s) with DCSync rights")

    if results:
        print_warning("[!] Non-admin accounts with DCSync is a critical finding!")
        print_table(
            ["Principal", "Type", "Domain"], [[r["name"], r["type"], r["domain"]] for r in results]
        )
        print_abuse_info("DCSync", results, extract_domain(results, domain))

    return result_count
