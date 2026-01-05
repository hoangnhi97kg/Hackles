"""ADCS relay targets via NTLM coercion (ESC8)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Coercion Relay to ADCS (ESC8)",
    category="Lateral Movement",
    default=True,
    severity=Severity.CRITICAL,
)
def get_coerce_relay_adcs(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find NTLM coercion to ADCS relay paths (ESC8).

    Identifies computers that can be coerced to authenticate and
    relayed to ADCS web enrollment to request certificates.
    This is ESC8 - a critical privilege escalation path.
    """
    domain_filter = "AND toUpper(source.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (source)-[:CoerceAndRelayNTLMToADCS]->(ca:EnterpriseCA)
    {f"WHERE {domain_filter[4:]}" if domain_filter else ""}
    RETURN source.name AS source,
           source.operatingsystem AS source_os,
           ca.name AS ca_target
    ORDER BY source.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Coercion Relay to ADCS (ESC8)", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} ADCS relay path(s)")

    if results:
        print_warning(
            "[!] CRITICAL ESC8: Coerce -> Relay to ADCS -> Request certificate as victim!"
        )
        print_warning("    Attack: PetitPotam/PrinterBug -> ntlmrelayx -> Certipy")
        print_table(
            ["Source", "Source OS", "CA Target"],
            [[r["source"], r.get("source_os", "N/A"), r["ca_target"]] for r in results],
        )

    return result_count
