"""SMB relay targets via NTLM coercion."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Coercion Relay to SMB",
    category="Lateral Movement",
    default=True,
    severity=Severity.HIGH,
)
def get_coerce_relay_smb(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find NTLM coercion to SMB relay paths.

    Identifies computers that can be coerced to authenticate and
    relayed to SMB for code execution or credential dumping.
    Requires SMB signing to be disabled on target.
    """
    domain_filter = "AND toUpper(source.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (source)-[:CoerceAndRelayNTLMToSMB]->(target)
    {f"WHERE {domain_filter[4:]}" if domain_filter else ""}
    RETURN source.name AS source,
           source.operatingsystem AS source_os,
           target.name AS target
    ORDER BY source.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Coercion Relay to SMB", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} SMB relay path(s)")

    if results:
        print_warning("[!] Coerce source -> Relay to SMB -> Code execution on target")
        print_warning("    Requires: SMB signing disabled on target")
        print_table(
            ["Source", "Source OS", "Relay Target"],
            [[r["source"], r.get("source_os", "N/A"), r["target"]] for r in results],
        )

    return result_count
