"""All DCSync Principals"""

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
    name="All DCSync Principals", category="Credentials", default=True, severity=Severity.CRITICAL
)
def get_dcsync_principals(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find all principals with DCSync rights (GetChanges + GetChangesAll)"""
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[r:DCSync|GetChanges|GetChangesAll]->(d:Domain)
    {domain_filter.replace('AND', 'WHERE') if domain else ''}
    WITH n, d, collect(type(r)) AS rights
    RETURN n.name AS principal, {node_type('n')} AS type,
           d.name AS domain,
           'DCSync' IN rights OR ('GetChanges' IN rights AND 'GetChangesAll' IN rights) AS can_dcsync,
           'GetChanges' IN rights AS has_getchanges,
           'GetChangesAll' IN rights AS has_getchangesall,
           n.enabled AS enabled
    ORDER BY can_dcsync DESC, type, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("All DCSync Principals", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} principal(s) with replication rights")

    if results:
        full_dcsync = sum(1 for r in results if r["can_dcsync"])
        partial = result_count - full_dcsync

        if full_dcsync:
            print_warning(f"[!] {full_dcsync} principal(s) can perform FULL DCSync!")
        if partial:
            print_warning(f"    {partial} principal(s) have partial replication rights")
        print()

        # Expected principals with DCSync
        print("    Expected principals with DCSync:")
        print("    - Domain Controllers (group)")
        print("    - Enterprise Domain Controllers")
        print("    - Administrators")
        print()
        print("    Unexpected principals should be investigated!")
        print()

        print_table(
            ["Principal", "Type", "Domain", "Full DCSync", "GetChanges", "GetChangesAll"],
            [
                [
                    r["principal"],
                    r["type"],
                    r["domain"],
                    r["can_dcsync"],
                    r["has_getchanges"],
                    r["has_getchangesall"],
                ]
                for r in results
            ],
        )

        # Only show abuse for full DCSync
        dcsync_results = [r for r in results if r["can_dcsync"]]
        if dcsync_results:
            print_abuse_info(
                "DCSync",
                [{"principal": r["principal"]} for r in dcsync_results],
                extract_domain(results, domain),
            )

    return result_count
