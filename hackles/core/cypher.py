"""Cypher query helpers for BloodHound CE"""

import re


def node_type(var: str = "n") -> str:
    """
    Generate Cypher CASE expression to get semantic node type.
    BloodHound CE nodes have multiple labels (e.g., Base, Group), so we
    check for specific labels in order of preference.
    """
    # Validate variable name to prevent Cypher injection
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")
    return f"""CASE
        WHEN {var}:User THEN 'User'
        WHEN {var}:Group THEN 'Group'
        WHEN {var}:Computer THEN 'Computer'
        WHEN {var}:Domain THEN 'Domain'
        WHEN {var}:GPO THEN 'GPO'
        WHEN {var}:OU THEN 'OU'
        WHEN {var}:Container THEN 'Container'
        WHEN {var}:EnterpriseCA THEN 'EnterpriseCA'
        WHEN {var}:CertTemplate THEN 'CertTemplate'
        WHEN {var}:NTAuthStore THEN 'NTAuthStore'
        WHEN {var}:RootCA THEN 'RootCA'
        WHEN {var}:AIACA THEN 'AIACA'
        ELSE labels({var})[0]
    END"""


def owned_filter(var: str = "n") -> str:
    """Generate Cypher WHERE clause to filter for owned principals"""
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")
    return f"({var}:Tag_Owned OR 'owned' IN COALESCE({var}.system_tags, []) OR {var}.owned = true)"


def tier_zero_filter(var: str = "n") -> str:
    """Generate Cypher WHERE clause to filter for Tier Zero principals"""
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")
    return f"({var}:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE({var}.system_tags, []))"
