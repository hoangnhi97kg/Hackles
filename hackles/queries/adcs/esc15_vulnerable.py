"""ADCS ESC15 Vulnerable (CVE-2024-49019)"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain


if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="ADCS ESC15 Vulnerable (CVE-2024-49019)",
    category="ADCS",
    default=True,
    severity=Severity.HIGH
)
def get_esc15_vulnerable(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find ESC15 vulnerable templates (CVE-2024-49019)"""
    domain_filter = "AND toUpper(ct.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
    WHERE ct.schemaversion = 1
    AND ct.enrolleesuppliessubject = true
    {domain_filter}
    RETURN ct.name AS template, ct.schemaversion AS version, ca.name AS ca, ct.domain AS domain
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC15 Vulnerable Templates (CVE-2024-49019)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC15 vulnerable template(s)")

    if results:
        print_warning("Version 1 templates with enrollee supplies subject are vulnerable to EKUwu attack!")
        print_table(
            ["Template", "Schema Version", "CA", "Domain"],
            [[r["template"], r["version"], r["ca"], r["domain"]] for r in results]
        )
        print_abuse_info("ADCSESC15", results, extract_domain(results, domain))

    return result_count
