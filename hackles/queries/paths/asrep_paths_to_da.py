"""Shortest Paths: AS-REP Roastable -> DA"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.config import config
from hackles.display.colors import Severity
from hackles.display.paths import print_paths_grouped
from hackles.display.tables import print_header, print_subheader, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Shortest Paths: AS-REP Roastable -> DA",
    category="Attack Paths",
    default=True,
    severity=Severity.CRITICAL,
)
def get_asrep_paths_to_da(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find shortest paths from AS-REP roastable users to Domain Admins"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Rewritten to avoid cartesian product warning
    query = f"""
    MATCH (u:User {{dontreqpreauth: true}})
    WHERE u.enabled = true
    {domain_filter}
    WITH u
    MATCH (g:Group)
    WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
    WITH u, g
    MATCH p=shortestPath((u)-[*1..{config.max_path_depth}]->(g))
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

    if not print_header(
        "Shortest Paths: AS-REP Roastable -> Domain Admins", severity, result_count
    ):
        return result_count
    print_subheader(f"Found {result_count} path(s) from AS-REP roastable to DA")

    if results:
        print_warning("AS-REP roast these users, crack password, then follow path to DA!")
        print_paths_grouped(results)
        # Extract starting user names for abuse info
        targets = [{"name": r["nodes"][0]} for r in results if r.get("nodes")]
        print_abuse_info("ASREPRoasting", targets, domain)

    return result_count
