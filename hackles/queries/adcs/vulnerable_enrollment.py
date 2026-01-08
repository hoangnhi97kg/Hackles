"""ADCS Vulnerable Enrollment"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS Vulnerable Enrollment", category="ADCS", default=True, severity=Severity.HIGH
)
def get_vulnerable_enrollment(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get enrollment rights on templates with enrollee supplies subject"""
    domain_filter = "AND toUpper(ct.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:Enroll|AutoEnroll]->(ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
    WHERE ct.enrolleesuppliessubject = true
    AND (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type("n")} AS type,
        ct.name AS template,
        ca.name AS ca
    ORDER BY ct.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS - Enrollment on Vulnerable Templates", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} vulnerable enrollment right(s) (limit 100)")

    if results:
        print_table(
            ["Principal", "Type", "Template", "CA"],
            [[r["principal"], r["type"], r["template"], r["ca"]] for r in results],
        )

    return result_count
