"""Well-known Active Directory RID constants.

These are relative identifiers (RIDs) for built-in security principals.
Object IDs end with these suffixes: <DOMAIN_SID>-<RID>

Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
"""

# Domain-level groups (relative to domain SID)
RID_DOMAIN_ADMINS = "-512"
RID_DOMAIN_USERS = "-513"
RID_DOMAIN_GUESTS = "-514"
RID_DOMAIN_COMPUTERS = "-515"
RID_DOMAIN_CONTROLLERS = "-516"
RID_CERT_PUBLISHERS = "-517"
RID_SCHEMA_ADMINS = "-518"
RID_ENTERPRISE_ADMINS = "-519"
RID_GROUP_POLICY_CREATOR_OWNERS = "-520"
RID_READONLY_DOMAIN_CONTROLLERS = "-521"
RID_CLONEABLE_CONTROLLERS = "-522"
RID_PROTECTED_USERS = "-525"
RID_KEY_ADMINS = "-526"
RID_ENTERPRISE_KEY_ADMINS = "-527"

# Built-in local groups (S-1-5-32-*)
RID_ADMINISTRATORS = "-544"
RID_USERS = "-545"
RID_GUESTS = "-546"
RID_POWER_USERS = "-547"
RID_ACCOUNT_OPERATORS = "-548"
RID_SERVER_OPERATORS = "-549"
RID_PRINT_OPERATORS = "-550"
RID_BACKUP_OPERATORS = "-551"
RID_REPLICATORS = "-552"
RID_REMOTE_DESKTOP_USERS = "-555"
RID_NETWORK_CONFIGURATION_OPS = "-556"
