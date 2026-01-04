"""Machine Account Quota"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Machine Account Quota", category="Basic Info", default=True, severity=Severity.INFO
)
def get_machine_account_quota(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Check machine account quota - can users add computers?"""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (d:Domain)
    {domain_filter}
    RETURN
        d.name AS domain,
        d.machineaccountquota AS maq
    """
    results = bh.run_query(query, params)
    result_count = sum(1 for r in results if r.get("maq") and r.get("maq") > 0)

    if not print_header("Machine Account Quota (MAQ)", severity, result_count):
        return result_count

    if results:
        for r in results:
            maq = r.get("maq")
            domain_name = r.get("domain")
            if maq is None:
                print_subheader(f"{domain_name}: MAQ not collected")
            elif maq > 0:
                print_warning(f"[!] {domain_name}: MAQ = {maq} (users CAN add computers)")
                print_subheader("This enables RBCD attacks without existing computer access!")
            else:
                print_subheader(f"{domain_name}: MAQ = {maq} (users cannot add computers)")

    return result_count
