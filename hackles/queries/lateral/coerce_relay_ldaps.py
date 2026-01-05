"""LDAPS relay targets via NTLM coercion."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Coercion Relay to LDAPS",
    category="Lateral Movement",
    default=True,
    severity=Severity.HIGH,
)
def get_coerce_relay_ldaps(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find NTLM coercion to LDAPS relay paths.

    Identifies computers that can be coerced to authenticate and
    relayed to LDAPS. This bypasses LDAP signing requirements
    but requires channel binding to be disabled.
    """
    domain_filter = "AND toUpper(source.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (source)-[:CoerceAndRelayNTLMToLDAPS]->(target)
    {f"WHERE {domain_filter[4:]}" if domain_filter else ""}
    RETURN source.name AS source,
           source.operatingsystem AS source_os,
           target.name AS target
    ORDER BY source.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Coercion Relay to LDAPS", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} LDAPS relay path(s)")

    if results:
        print_warning("[!] Coerce source -> Relay to LDAPS -> RBCD/Shadow Credentials attack")
        print_warning("    Bypasses LDAP signing, requires channel binding disabled")
        print_table(
            ["Source", "Source OS", "Relay Target"],
            [[r["source"], r.get("source_os", "N/A"), r["target"]] for r in results],
        )

    return result_count
