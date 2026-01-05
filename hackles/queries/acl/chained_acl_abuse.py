"""Chained ACL abuse detection - multi-hop privilege escalation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Chained ACL Abuse to High-Value",
    category="ACL Abuse",
    default=True,
    severity=Severity.CRITICAL,
)
def get_chained_acl_abuse(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find two-hop ACL chains leading to high-value targets.

    Identifies principals that can modify an intermediate object's DACL,
    where that intermediate object has dangerous permissions on high-value targets.
    Attack chain: WriteDacl -> Pivot -> GenericAll/WriteDacl/WriteOwner -> High-Value
    """
    domain_filter = "AND toUpper(highvalue.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:WriteDacl|WriteOwner]->(pivot)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'
    AND NOT n.objectid ENDS WITH '-519'
    MATCH (pivot)-[:GenericAll|WriteDacl|WriteOwner|ForceChangePassword]->(highvalue)
    WHERE (highvalue.highvalue = true OR highvalue:Tag_Tier_Zero)
    AND highvalue <> n
    {domain_filter}
    RETURN DISTINCT
        n.name AS attacker,
        {node_type("n")} AS attacker_type,
        pivot.name AS pivot,
        {node_type("pivot")} AS pivot_type,
        highvalue.name AS target
    ORDER BY n.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Chained ACL Abuse to High-Value", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} two-hop ACL chain(s)")

    if results:
        print_warning("[!] CRITICAL: Multi-hop privilege escalation to high-value targets!")
        print_warning("    Attack: Modify pivot DACL -> Grant self GenericAll -> Attack target")
        print_table(
            ["Attacker", "Type", "Pivot Object", "Pivot Type", "Final Target"],
            [
                [r["attacker"], r["attacker_type"], r["pivot"], r["pivot_type"], r["target"]]
                for r in results
            ],
        )

    return result_count
