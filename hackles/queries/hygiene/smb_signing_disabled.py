"""SMB Signing Disabled"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="SMB Signing Disabled", category="Security Hygiene", default=True, severity=Severity.HIGH
)
def get_smb_signing_disabled(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find computers with SMB signing disabled (NTLM relay targets)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE c.enabled = true
    AND c.smbsigning = false
    {domain_filter}
    RETURN c.name AS computer, c.operatingsystem AS os
    ORDER BY c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("SMB Signing Disabled", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with SMB signing disabled")

    if results:
        print_warning("These systems are vulnerable to NTLM relay attacks!")
        print_table(["Computer", "Operating System"], [[r["computer"], r["os"]] for r in results])

    return result_count
