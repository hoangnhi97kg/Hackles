"""Users with Logon Scripts in Trusted Domains"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Logon Scripts in Trusted Domains",
    category="Security Hygiene",
    default=True,
    severity=Severity.HIGH
)
def get_logon_scripts_foreign(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find users with logon scripts stored in a different domain.

    Logon scripts in trusted domains create a cross-domain attack path.
    If the trusted domain is compromised, attackers can modify the script
    to execute code on machines in the trusting domain.
    """
    domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    {domain_filter}
    WHERE u.scriptpath IS NOT NULL
    AND u.scriptpath <> ''
    AND u.enabled = true
    WITH u,
        CASE
            WHEN u.scriptpath CONTAINS '\\\\'
            THEN split(replace(u.scriptpath, '\\\\', ''), '\\\\')[0]
            ELSE null
        END AS script_host
    WHERE script_host IS NOT NULL
    AND NOT toUpper(script_host) CONTAINS toUpper(split(u.domain, '.')[0])
    RETURN
        u.name AS user,
        u.domain AS user_domain,
        u.scriptpath AS script_path,
        script_host AS script_server
    ORDER BY u.domain, u.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Logon Scripts in Trusted Domains", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} user(s) with foreign domain logon scripts")

    if results:
        print_warning("[!] Logon scripts from other domains = cross-domain attack vector!")
        print_warning("[*] Compromising the script server allows code execution at logon")
        print_table(
            ["User", "Domain", "Script Path", "Script Server"],
            [[r["user"], r["user_domain"], r["script_path"], r["script_server"]] for r in results]
        )

    return result_count
