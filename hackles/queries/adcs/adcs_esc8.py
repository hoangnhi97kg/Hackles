"""ADCS ESC8 (Web Enrollment)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS ESC8 (Web Enrollment)", category="ADCS", default=True, severity=Severity.HIGH
)
def get_adcs_esc8(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """ADCS ESC8 - Web enrollment enabled (NTLM relay to ADCS)"""
    domain_filter = "AND toUpper(eca.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (eca:EnterpriseCA)
    WHERE eca.webenrollmentenabled = true
    {domain_filter}
    RETURN eca.name AS ca, eca.dnshostname AS host
    ORDER BY eca.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC8 (Web Enrollment)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} CA(s) with web enrollment enabled")

    if results:
        print_warning("[!] NTLM relay to web enrollment endpoint to obtain certificates!")
        print_table(["CA Name", "Hostname"], [[r["ca"], r["host"]] for r in results])
        print_abuse_info("ADCSESC8", results, extract_domain(results, domain))

    return result_count
