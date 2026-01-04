"""ADCS ESC3 - Enrollment Agent Abuse"""

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
    name="ADCS ESC3 - Enrollment Agent Abuse",
    category="ADCS",
    default=True,
    severity=Severity.CRITICAL,
)
def get_esc3_enrollment_agent(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC3 vulnerable configurations - Enrollment Agent abuse.

    ESC3 allows principals to request certificates on behalf of other users
    using enrollment agent templates.
    """
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Look for Certificate Request Agent templates (OID 1.3.6.1.4.1.311.20.2.1)
    query = f"""
    MATCH (u)-[:Enroll]->(c:CertTemplate)
    WHERE '1.3.6.1.4.1.311.20.2.1' IN c.effectiveekus
    AND (u.admincount IS NULL OR u.admincount = false)
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

    if not print_header("ADCS ESC3 - Enrollment Agent Templates", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} enrollment right(s) on Enrollment Agent templates (limit 100)"
    )

    if results:
        print_warning(
            "[!] Enrollment Agent templates allow requesting certificates on behalf of other users!"
        )
        print_table(
            ["Principal", "Type", "Template", "CA"],
            [[r["principal"], r["type"], r["template"], r.get("ca", "Unknown")] for r in results],
        )
        print_abuse_info("ADCSESC3", results, extract_domain(results, domain))

    return result_count
