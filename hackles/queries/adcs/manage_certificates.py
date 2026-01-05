"""ManageCertificates rights detection for ADCS abuse."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ManageCertificates Rights",
    category="ADCS",
    default=True,
    severity=Severity.HIGH,
)
def get_manage_certificates(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find principals with ManageCertificates rights on Certificate Authorities.

    ManageCertificates allows issuing and revoking certificates, which can be
    abused to issue certificates for other users (ESC7 variant).
    """
    domain_filter = "AND toUpper(ca.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:ManageCertificates]->(ca:EnterpriseCA)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'
    AND NOT n.objectid ENDS WITH '-519'
    {domain_filter}
    RETURN n.name AS principal,
           {node_type("n")} AS type,
           ca.name AS ca_name
    ORDER BY ca.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ManageCertificates Rights", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} principal(s) with ManageCertificates")

    if results:
        print_warning("[!] Can issue/revoke certificates - potential ESC7 attack path!")
        print_table(
            ["Principal", "Type", "CA Name"],
            [[r["principal"], r["type"], r["ca_name"]] for r in results],
        )

    return result_count
