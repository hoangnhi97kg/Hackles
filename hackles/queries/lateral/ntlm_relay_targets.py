"""NTLM Relay Targets (SMB Signing)"""

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
    name="NTLM Relay Targets (SMB Signing)",
    category="Lateral Movement",
    default=True,
    severity=Severity.HIGH,
)
def get_ntlm_relay_targets(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """NTLM relay opportunities - computers with admin rights to SMB signing disabled targets"""
    domain_filter = "WHERE toUpper(c1.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c1:Computer)-[:AdminTo]->(c2:Computer {{signing: false}})
    {domain_filter}
    RETURN c1.name AS source, c2.name AS relay_target, c2.operatingsystem AS os
    ORDER BY c2.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("NTLM Relay Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} NTLM relay opportunity(ies)")

    if results:
        print_warning("[!] Coerce source → Relay to target (SMB signing disabled)!")
        print_table(
            ["Source Computer", "Relay Target", "OS"],
            [[r["source"], r["relay_target"], r["os"]] for r in results],
        )
        print_abuse_info("NTLMRelay", results, extract_domain(results, domain))

    return result_count
