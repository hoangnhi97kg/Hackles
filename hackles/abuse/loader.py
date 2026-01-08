"""YAML template loader for abuse commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

# Cache for loaded templates
_template_cache: dict[str, dict[str, Any]] = {}

# Map edge types to template files
EDGE_TO_TEMPLATE = {
    # ACL edges
    "GenericAll": "acl",
    "GenericWrite": "acl",
    "WriteDacl": "acl",
    "WriteOwner": "acl",
    "ForceChangePassword": "acl",
    "AddMember": "acl",
    "AllExtendedRights": "acl",
    "Owns": "acl",
    "AddKeyCredentialLink": "acl",
    "WriteSPN": "acl",
    "AddSelf": "acl",
    "ReadLAPSPassword": "credentials",
    "ReadGMSAPassword": "credentials",
    "WriteAccountRestrictions": "acl",
    "DCSync": "credentials",
    "GetChanges": "credentials",
    "GetChangesAll": "credentials",
    # Delegation edges
    "AllowedToDelegate": "delegation",
    "AllowedToAct": "delegation",
    # Lateral movement edges
    "AdminTo": "lateral",
    "CanRDP": "lateral",
    "CanPSRemote": "lateral",
    "ExecuteDCOM": "lateral",
    "HasSession": "lateral",
    "SQLAdmin": "lateral",
    # GPO edges
    "GPLink": "gpo",
    # Azure edges
    "AZAddMembers": "azure",
    "AZAddOwner": "azure",
    "AZAddSecret": "azure",
    "AZGlobalAdmin": "azure",
    "AZPrivilegedRoleAdmin": "azure",
    "AZMGAddMember": "azure",
    "AZMGAddOwner": "azure",
    "AZMGAddSecret": "azure",
    "SyncedToEntraUser": "azure",
    "AZContributor": "azure",
    "AZVMContributor": "azure",
    "AZKeyVaultReader": "azure",
    "AZResetPassword": "azure",
    "AZUserAccessAdministrator": "azure",
    "AZOwner": "azure",
}

# Map query names to template files and keys
QUERY_TO_TEMPLATE = {
    "kerberoastable": ("credentials", "Kerberoasting"),
    "asrep": ("credentials", "ASREPRoasting"),
    "dcsync": ("credentials", "DCSync"),
    "unconstrained": ("delegation", "Unconstrained"),
    "constrained": ("delegation", "Constrained"),
    "rbcd": ("delegation", "RBCD"),
    "esc1": ("adcs", "ESC1"),
    "esc2": ("adcs", "ESC2"),
    "esc3": ("adcs", "ESC3"),
    "esc4": ("adcs", "ESC4"),
    "esc6": ("adcs", "ESC6"),
    "esc8": ("adcs", "ESC8"),
    "passwd_notreqd": ("credentials", "PasswdNotReqd"),
    "dnsadmins": ("groups", "DNSAdmins"),
    "backup_operators": ("groups", "BackupOperators"),
    "server_operators": ("groups", "ServerOperators"),
    "print_operators": ("groups", "PrintOperators"),
    "account_operators": ("groups", "AccountOperators"),
    "gpo_creators": ("groups", "GPOCreators"),
    "laps": ("credentials", "LAPS"),
    "gmsa": ("credentials", "GMSA"),
    "print_spooler": ("coercion", "PrintSpooler"),
    "petitpotam": ("coercion", "PetitPotam"),
    "shadow_credentials": ("credentials", "ShadowCredentials"),
    "esc5": ("adcs", "ESC5"),
    "esc7": ("adcs", "ESC7"),
    "esc9": ("adcs", "ESC9"),
    "esc10": ("adcs", "ESC10"),
    "esc11": ("adcs", "ESC11"),
    "esc13": ("adcs", "ESC13"),
    "esc15": ("adcs", "ESC15"),
    "golden_cert": ("adcs", "GoldenCert"),
    "aadconnect": ("azure", "AADConnect"),
    "azure_vm": ("azure", "AZVMContributor"),
    "keyvault": ("azure", "AZKeyVaultReader"),
}


def _get_templates_dir() -> Path:
    """Get the path to the templates directory."""
    return Path(__file__).parent / "templates"


def _load_template(name: str) -> dict[str, Any]:
    """Load a YAML template file by name (cached)."""
    if name in _template_cache:
        return _template_cache[name]

    template_path = _get_templates_dir() / f"{name}.yaml"
    if not template_path.exists():
        _template_cache[name] = {}
        return {}

    try:
        with open(template_path) as f:
            data = yaml.safe_load(f) or {}
            _template_cache[name] = data
            return data
    except (yaml.YAMLError, OSError):
        _template_cache[name] = {}
        return {}


def get_abuse_commands(edge_type: str, target_type: str) -> Optional[dict[str, Any]]:
    """Get abuse commands for an edge type and target type.

    Args:
        edge_type: The edge/relationship type (GenericAll, WriteDacl, etc.)
        target_type: The target node type (User, Computer, Group, etc.)

    Returns:
        Dict with description, commands, opsec, references or None
    """
    template_name = EDGE_TO_TEMPLATE.get(edge_type)
    if not template_name:
        return None

    template = _load_template(template_name)
    edge_data = template.get(edge_type, {})
    return edge_data.get(target_type)


def get_query_abuse_commands(query_name: str) -> Optional[dict[str, Any]]:
    """Get abuse commands for a specific query type.

    Args:
        query_name: The query identifier (kerberoastable, asrep, etc.)

    Returns:
        Dict with description, commands, opsec, references or None
    """
    mapping = QUERY_TO_TEMPLATE.get(query_name.lower())
    if not mapping:
        return None

    template_name, key = mapping
    template = _load_template(template_name)
    return template.get(key)


def clear_cache() -> None:
    """Clear the template cache (useful for testing)."""
    _template_cache.clear()
