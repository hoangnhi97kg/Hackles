"""Owned -> High Value Targets"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.paths import print_paths_grouped
from hackles.display.tables import print_header, print_subheader
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Owned -> High Value Targets", category="Owned", default=True, severity=Severity.CRITICAL
)
def get_owned_to_high_value(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find shortest paths from owned principals to any high value target"""
    # Rewritten to avoid cartesian product warning
    # BloodHound CE uses 'admin_tier_0' for tier zero assets
    from_owned_filter = "AND toUpper(n.name) = toUpper($from_owned)" if config.from_owned else ""
    params = {"from_owned": config.from_owned} if config.from_owned else {}

    query = f"""
    MATCH (n)
    WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)
    {from_owned_filter}
    WITH n
    MATCH (hvt)
    WHERE ('admin_tier_0' IN hvt.system_tags OR 'high_value' IN hvt.system_tags OR hvt.highvalue = true)
    AND n <> hvt
    WITH n, hvt
    MATCH p=shortestPath((n)-[*1..{config.max_path_depth}]->(hvt))
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

    if not print_header("Shortest Paths: Owned -> High Value Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} path(s) from owned to high value")

    if results:
        print_paths_grouped(results)

    return result_count
