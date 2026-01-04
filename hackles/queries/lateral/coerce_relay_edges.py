"""Coerce & Relay Edges"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Coerce & Relay Edges", category="Lateral Movement", default=True, severity=Severity.HIGH
)
def get_coerce_relay_edges(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """BloodHound CE native coerce and relay edges"""
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[r:CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToSMB]->(m)
    {domain_filter}
    RETURN n.name AS source, type(r) AS relay_type, m.name AS target
    ORDER BY type(r), n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Coerce & Relay Edges", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} coerce/relay path(s)")

    if results:
        print_table(
            ["Source", "Relay Type", "Target"],
            [[r["source"], r["relay_type"], r["target"]] for r in results],
        )
        print_abuse_info("NTLMRelay", results, extract_domain(results, domain))

    return result_count
