"""Busiest Attack Paths Analysis"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Busiest Attack Path Nodes",
    category="Attack Paths",
    default=True,
    severity=Severity.MEDIUM,
)
def get_busiest_paths(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find nodes that appear most frequently in attack paths (chokepoints)"""
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)
    {domain_filter}
    WITH n
    OPTIONAL MATCH (n)-[r]->()
    WHERE type(r) IN ['MemberOf', 'AdminTo', 'HasSession', 'GenericAll', 'GenericWrite',
                      'WriteDacl', 'WriteOwner', 'ForceChangePassword', 'AddMember',
                      'AllExtendedRights', 'AddSelf', 'Contains', 'GPLink',
                      'Owns', 'DCSync', 'GetChanges', 'GetChangesAll']
    WITH n, count(r) AS outbound_edges
    OPTIONAL MATCH ()-[r2]->(n)
    WHERE type(r2) IN ['MemberOf', 'AdminTo', 'HasSession', 'GenericAll', 'GenericWrite',
                       'WriteDacl', 'WriteOwner', 'ForceChangePassword', 'AddMember',
                       'AllExtendedRights', 'AddSelf', 'Contains', 'GPLink',
                       'Owns', 'DCSync', 'GetChanges', 'GetChangesAll']
    WITH n, outbound_edges, count(r2) AS inbound_edges
    WHERE outbound_edges + inbound_edges > 5
    RETURN n.name AS node, {node_type('n')} AS type, n.domain AS domain,
           outbound_edges, inbound_edges,
           outbound_edges + inbound_edges AS total_edges
    ORDER BY total_edges DESC
    LIMIT 30
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Busiest Attack Path Nodes", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} high-connectivity node(s)")

    if results:
        print_warning("[*] These nodes appear frequently in attack paths")
        print_warning("    Securing these 'chokepoints' can disrupt many attack chains")

        # Analyze by type
        groups = sum(1 for r in results if r["type"] == "Group")
        users = sum(1 for r in results if r["type"] == "User")
        computers = sum(1 for r in results if r["type"] == "Computer")
        print_warning(f"    Breakdown: {groups} groups, {users} users, {computers} computers")

        print_table(
            ["Node", "Type", "Domain", "Outbound", "Inbound", "Total"],
            [
                [
                    r["node"],
                    r["type"],
                    r["domain"],
                    r["outbound_edges"],
                    r["inbound_edges"],
                    r["total_edges"],
                ]
                for r in results
            ],
        )

    return result_count
