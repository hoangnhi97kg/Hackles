"""Reversible Encryption"""

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
    name="Reversible Encryption",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
)
def get_reversible_encryption(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find accounts with reversible encryption enabled (password recoverable)"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # useraccountcontrol flag 128 = ENCRYPTED_TEXT_PASSWORD_ALLOWED
    query = f"""
    MATCH (u:User)
    WHERE u.enabled = true
    AND u.useraccountcontrol IS NOT NULL
    {domain_filter}
    RETURN
        u.name AS name,
        u.displayname AS displayname,
        u.useraccountcontrol AS uac,
        u.admincount AS admincount
    """
    results = bh.run_query(query, params)

    # Filter for UAC flag 128 (reversible encryption)
    # Cast to int since Neo4j may return float
    filtered = [r for r in results if r.get("uac") and (int(r["uac"]) & 128)]
    result_count = len(filtered)

    if not print_header("Reversible Encryption Enabled", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} account(s) with reversible encryption")

    if filtered:
        print_warning("[!] Passwords for these accounts can be recovered from AD!")
        print_table(
            ["Name", "Display Name", "Admin"],
            [[r["name"], r["displayname"], r["admincount"]] for r in filtered],
        )
        print_abuse_info("ReversibleEncryption", filtered, extract_domain(filtered, domain))

    return result_count
