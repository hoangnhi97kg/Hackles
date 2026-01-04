"""Risk scoring and exposure metrics"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


def calculate_exposure_metrics(bh: BloodHoundCE, domain: Optional[str] = None) -> Dict[str, Any]:
    """Calculate domain exposure metrics for risk scoring.

    Returns a dictionary of metrics useful for assessing domain security posture.
    """
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    user_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    comp_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    metrics = {}

    # Total enabled users
    query = f"""
    MATCH (n:User)
    {domain_filter}
    RETURN
        count(CASE WHEN n.enabled = true THEN 1 END) AS enabled_users,
        count(n) AS total_users
    """
    results = bh.run_query(query, params)
    if results:
        metrics["total_users"] = results[0].get("total_users", 0)
        metrics["enabled_users"] = results[0].get("enabled_users", 0)

    # Users with path to Domain Admins
    query = f"""
    MATCH (u:User {{enabled: true}})
    WHERE EXISTS {{
        MATCH p=(u)-[*1..6]->(g:Group)
        WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
    }}
    {user_filter}
    RETURN count(DISTINCT u) AS users_with_path
    """
    results = bh.run_query(query, params)
    if results:
        metrics["users_with_path_to_da"] = results[0].get("users_with_path", 0)

    # Computers without LAPS
    query = f"""
    MATCH (c:Computer)
    WHERE c.enabled = true
    {comp_filter}
    RETURN
        count(c) AS total_computers,
        count(CASE WHEN c.haslaps = false OR c.haslaps IS NULL THEN 1 END) AS no_laps
    """
    results = bh.run_query(query, params)
    if results:
        metrics["total_computers"] = results[0].get("total_computers", 0)
        metrics["computers_without_laps"] = results[0].get("no_laps", 0)

    # Tier Zero count
    query = f"""
    MATCH (n)
    WHERE (n:Tag_Tier_Zero OR 'admin_tier_0' IN n.system_tags)
    {user_filter.replace('u.', 'n.')}
    RETURN count(n) AS tier_zero_count
    """
    results = bh.run_query(query, params)
    if results:
        metrics["tier_zero_count"] = results[0].get("tier_zero_count", 0)

    # Kerberoastable users with admin rights
    query = f"""
    MATCH (u:User {{enabled: true, hasspn: true}})
    WHERE (u.admincount = true OR EXISTS((u)-[:AdminTo]->(:Computer)))
    {user_filter}
    RETURN count(DISTINCT u) AS kerberoastable_admins
    """
    results = bh.run_query(query, params)
    if results:
        metrics["kerberoastable_admins"] = results[0].get("kerberoastable_admins", 0)

    # AS-REP roastable users
    asrep_domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (u:User {{enabled: true, dontreqpreauth: true}})
    {asrep_domain_filter}
    RETURN count(u) AS asrep_users
    """
    results = bh.run_query(query, params)
    if results:
        metrics["asrep_roastable"] = results[0].get("asrep_users", 0)

    # Unconstrained delegation (non-DC)
    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true, enabled: true}})
    WHERE NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {comp_filter}
    RETURN count(c) AS unconstrained_non_dc
    """
    results = bh.run_query(query, params)
    if results:
        metrics["unconstrained_delegation_non_dc"] = results[0].get("unconstrained_non_dc", 0)

    # Domain Admins count
    query = f"""
    MATCH (u:User)-[:MemberOf*1..]->(g:Group)
    WHERE (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519')
    AND u.enabled = true
    {user_filter}
    RETURN count(DISTINCT u) AS domain_admin_count
    """
    results = bh.run_query(query, params)
    if results:
        metrics["domain_admin_count"] = results[0].get("domain_admin_count", 0)

    # Calculate percentages
    if metrics.get("enabled_users", 0) > 0:
        path_pct = (metrics.get("users_with_path_to_da", 0) / metrics["enabled_users"]) * 100
        metrics["pct_users_with_path_to_da"] = round(path_pct, 1)

    if metrics.get("total_computers", 0) > 0:
        laps_pct = (metrics.get("computers_without_laps", 0) / metrics["total_computers"]) * 100
        metrics["pct_computers_without_laps"] = round(laps_pct, 1)

    return metrics


def calculate_risk_score(metrics: Dict[str, Any]) -> int:
    """Calculate an overall risk score from 0-100 based on exposure metrics.

    Higher score = higher risk.
    """
    score = 0
    max_score = 100

    # Weight factors (total should equal max_score potential)
    weights = {
        "pct_users_with_path_to_da": 25,  # Very high risk
        "pct_computers_without_laps": 15,  # Medium risk
        "kerberoastable_admins": 20,  # High risk
        "asrep_roastable": 10,  # Medium risk
        "unconstrained_delegation_non_dc": 15,  # High risk
        "domain_admin_count": 15,  # More DAs = more attack surface
    }

    # Path to DA (25 points max)
    pct_path = metrics.get("pct_users_with_path_to_da", 0)
    if pct_path > 50:
        score += 25
    elif pct_path > 20:
        score += 20
    elif pct_path > 10:
        score += 15
    elif pct_path > 5:
        score += 10
    elif pct_path > 0:
        score += 5

    # Computers without LAPS (15 points max)
    pct_no_laps = metrics.get("pct_computers_without_laps", 0)
    if pct_no_laps > 80:
        score += 15
    elif pct_no_laps > 50:
        score += 10
    elif pct_no_laps > 20:
        score += 5

    # Kerberoastable admins (20 points max)
    kerb_admins = metrics.get("kerberoastable_admins", 0)
    if kerb_admins > 10:
        score += 20
    elif kerb_admins > 5:
        score += 15
    elif kerb_admins > 0:
        score += 10

    # AS-REP roastable (10 points max)
    asrep = metrics.get("asrep_roastable", 0)
    if asrep > 20:
        score += 10
    elif asrep > 5:
        score += 7
    elif asrep > 0:
        score += 4

    # Unconstrained delegation (15 points max)
    unconst = metrics.get("unconstrained_delegation_non_dc", 0)
    if unconst > 5:
        score += 15
    elif unconst > 2:
        score += 10
    elif unconst > 0:
        score += 5

    # DA count (15 points max - more DAs = higher risk)
    da_count = metrics.get("domain_admin_count", 0)
    if da_count > 50:
        score += 15
    elif da_count > 20:
        score += 10
    elif da_count > 10:
        score += 5

    return min(score, max_score)


def get_risk_rating(score: int) -> str:
    """Convert numeric risk score to a rating label."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "MINIMAL"
