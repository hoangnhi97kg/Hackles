"""Owned -> Domain Admins"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.paths import print_paths_grouped
from hackles.display.tables import print_header, print_subheader, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Owned -> Domain Admins", category="Owned", default=True, severity=Severity.CRITICAL
)
def get_shortest_paths_to_da(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get shortest paths from owned principals to Domain Admins"""
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    from_owned_filter = "AND toUpper(n.name) = toUpper($from_owned)" if config.from_owned else ""
    params = {}
    if domain:
        params["domain"] = domain
    if config.from_owned:
        params["from_owned"] = config.from_owned

    query = f"""
    MATCH p=shortestPath((n)-[*1..{config.max_path_depth}]->(g:Group))
    WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)
    AND (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519')
    {domain_filter}
    {from_owned_filter}
    RETURN
        [node IN nodes(p) | node.name] AS nodes,
        [node IN nodes(p) | CASE
            WHEN node:User THEN 'User'
            WHEN node:Group THEN 'Group'
            WHEN node:Computer THEN 'Computer'
            WHEN node:Domain THEN 'Domain'
            ELSE 'Other' END] AS node_types,
        [r IN relationships(p) | type(r)] AS relationships,
        length(p) AS path_length
    ORDER BY length(p)
    LIMIT {config.max_paths}
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Shortest Paths: Owned -> Domain Admins", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} path(s) from owned principals to Domain Admins")

    if results:
        print_warning("[!] These are your attack paths to Domain Admin!")
        print_paths_grouped(results)

    return result_count
