"""Cross-Domain Ownership"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Cross-Domain Object Ownership",
    category="Basic Info",
    default=True,
    severity=Severity.HIGH,
)
def get_cross_domain_ownership(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find objects owned by principals from different domains"""
    query = f"""
    MATCH (owner)-[:Owns]->(target)
    WHERE owner.domain <> target.domain
    AND owner.domain IS NOT NULL
    AND target.domain IS NOT NULL
    RETURN owner.name AS owner, owner.domain AS owner_domain,
           target.name AS target_object, target.domain AS target_domain,
           {node_type('target')} AS target_type
    ORDER BY owner.domain, target.domain
    LIMIT 100
    """
    results = bh.run_query(query)
    result_count = len(results)

    if not print_header("Cross-Domain Object Ownership", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} cross-domain ownership relationship(s)")

    if results:
        print_warning("[!] Objects owned by principals from OTHER domains!")
        print_warning("    Ownership allows granting any permissions on the object.")

        # Count unique domain pairs
        domain_pairs = set((r["owner_domain"], r["target_domain"]) for r in results)
        print_warning(f"    Spans {len(domain_pairs)} domain pair(s)")

        print_table(
            ["Owner", "Owner Domain", "Target Object", "Target Domain", "Type"],
            [
                [
                    r["owner"],
                    r["owner_domain"],
                    r["target_object"],
                    r["target_domain"],
                    r["target_type"],
                ]
                for r in results
            ],
        )

    return result_count
