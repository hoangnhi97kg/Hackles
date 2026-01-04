"""ADCS ESC2/ESC3 Any Purpose"""

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
    name="ADCS ESC2/ESC3 Any Purpose", category="ADCS", default=True, severity=Severity.HIGH
)
def get_any_purpose_templates(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get ESC2/ESC3 - Any Purpose certificate templates"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u)-[:Enroll]->(c:CertTemplate)
    WHERE '2.5.29.37.0' IN c.effectiveekus
    AND NOT u.objectid ENDS WITH '-512'
    AND NOT u.objectid ENDS WITH '-519'
    {domain_filter}
    OPTIONAL MATCH (c)-[:PublishedTo]->(ca:EnterpriseCA)
    RETURN
        u.name AS principal,
        {node_type('u')} AS type,
        c.name AS template,
        ca.name AS ca
    ORDER BY c.name, u.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC2/ESC3 - Any Purpose Templates", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} enrollment right(s) on Any Purpose templates (limit 100)"
    )

    if results:
        print_warning("[!] Any Purpose templates can be abused for client authentication!")
        print_table(
            ["Principal", "Type", "Template", "CA"],
            [[r["principal"], r["type"], r["template"], r.get("ca", "Unknown")] for r in results],
        )
        # ESC2 is the more common abuse path
        print_abuse_info("ADCSESC2", results, extract_domain(results, domain))

    return result_count
