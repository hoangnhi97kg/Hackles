"""Owned -> Unconstrained Delegation"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader
from hackles.display.paths import print_paths_grouped
from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.core.config import config


if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="Owned -> Unconstrained Delegation",
    category="Owned",
    default=True,
    severity=Severity.HIGH
)
def get_owned_to_unconstrained(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find paths from owned principals to unconstrained delegation systems"""
    from_owned_filter = "AND toUpper(owned.name) = toUpper($from_owned)" if config.from_owned else ""
    params = {"from_owned": config.from_owned} if config.from_owned else {}

    query = f"""
    MATCH (owned)
    WHERE (owned:Tag_Owned OR 'owned' IN owned.system_tags OR owned.owned = true)
    {from_owned_filter}
    WITH owned
    MATCH (target)
    WHERE target.unconstraineddelegation = true
    AND owned <> target
    WITH owned, target
    MATCH p=shortestPath((owned)-[*1..{config.max_path_depth}]->(target))
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

    if not print_header("Owned -> Unconstrained Delegation", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} path(s) to unconstrained delegation")

    if results:
        print_paths_grouped(results)
        # Extract target (last node) names for abuse info
        targets = [{"name": r["nodes"][-1]} for r in results if r.get("nodes")]
        print_abuse_info("UnconstrainedDelegation", targets, extract_domain(targets, None))

    return result_count
