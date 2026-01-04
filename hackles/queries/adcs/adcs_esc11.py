"""ADCS ESC11 (SAN Enabled)"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS ESC11 (SAN Enabled)", category="ADCS", default=True, severity=Severity.HIGH
)
def get_adcs_esc11(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """ADCS ESC11 - User-specified SAN enabled on CA"""
    domain_filter = "AND toUpper(eca.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (eca:EnterpriseCA)
    WHERE eca.isuserspecifiessanenabled = true
    {domain_filter}
    RETURN eca.name AS ca, eca.dnshostname AS host
    ORDER BY eca.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC11 (User SAN Enabled)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} CA(s) with user-specified SAN enabled")

    if results:
        print_warning("[!] CA allows user-specified Subject Alternative Name!")
        print_table(["CA Name", "Hostname"], [[r["ca"], r["host"]] for r in results])
        print_abuse_info("ADCSESC11", results, extract_domain(results, domain))

    return result_count
