"""GPO Interesting Names"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="GPO Interesting Names",
    category="ACL Abuse",
    default=True,
    severity=Severity.LOW
)
def get_gpo_interesting_names(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """GPOs with interesting names (password, credential, admin, deploy, etc.)"""
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:GPO)
    WHERE g.name =~ '(?i).*(password|credential|admin|service|deploy|install|laps|bitlocker|firewall|antivirus).*'
    {domain_filter}
    RETURN g.name AS gpo, g.gpcpath AS path
    ORDER BY g.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("GPO Interesting Names", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} GPO(s) with interesting names")

    if results:
        print_warning("[!] These GPOs may contain credentials or deployment configs!")
        print_table(
            ["GPO Name", "Path"],
            [[r["gpo"], r["path"]] for r in results]
        )
        print_abuse_info("GPOAbuse", results, extract_domain(results, domain))

    return result_count
