"""ADCS Escalation Paths (ESC1-13)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS Escalation Paths (ESC1-13)", category="ADCS", default=True, severity=Severity.HIGH
)
def get_adcs_escalation_paths(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get all ADCS escalation paths (ESC1-ESC13)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[r:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(m)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    OPTIONAL MATCH (m)-[:PublishedTo]->(ca:EnterpriseCA)
    RETURN
        n.name AS principal,
        {node_type('n')} AS type,
        type(r) AS escalation,
        m.name AS target,
        ca.name AS ca
    ORDER BY type(r), n.name
    LIMIT 200
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS Escalation Paths (ESC1-ESC13)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ADCS escalation path(s) (limit 200)")

    if results:
        # Group by escalation type
        esc_types = {}
        for r in results:
            esc = r["escalation"]
            if esc not in esc_types:
                esc_types[esc] = 0
            esc_types[esc] += 1

        print_subheader("Escalation Types Found:")
        for esc, count in sorted(esc_types.items()):
            print(f"      {esc}: {count}")

        print()
        print_table(
            ["Principal", "Type", "Escalation", "Target", "CA"],
            [
                [r["principal"], r["type"], r["escalation"], r["target"], r.get("ca", "-")]
                for r in results
            ],
        )

        # Print abuse info for each unique escalation type found
        extracted_domain = extract_domain(results, domain)
        for esc in sorted(esc_types.keys()):
            # Filter findings for this specific escalation type
            esc_findings = [r for r in results if r["escalation"] == esc]
            print_abuse_info(esc, esc_findings, extracted_domain)

    return result_count
