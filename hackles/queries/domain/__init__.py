"""Query functions for domain"""
from .domain_admins import get_domain_admins
from .domain_functional_level import get_domain_functional_level
from .domain_stats import get_domain_stats
from .domain_trusts import get_domain_trusts
from .external_trust_analysis import get_external_trust_analysis
from .foreign_group_membership import get_foreign_group_membership
from .high_value_targets import get_high_value_targets
from .machine_account_quota import get_machine_account_quota
from .sid_history_same_domain import get_sid_history_same_domain
from .single_dc import get_single_dc
from .tier_zero_count import get_tier_zero_count
from .cross_domain_ownership import get_cross_domain_ownership
from .trust_sid_filtering import get_trust_sid_filtering
from .azuread_sso import get_azuread_sso

__all__ = [
    'get_domain_admins',
    'get_domain_functional_level',
    'get_domain_stats',
    'get_domain_trusts',
    'get_external_trust_analysis',
    'get_foreign_group_membership',
    'get_high_value_targets',
    'get_machine_account_quota',
    'get_sid_history_same_domain',
    'get_single_dc',
    'get_tier_zero_count',
    'get_cross_domain_ownership',
    'get_trust_sid_filtering',
    'get_azuread_sso',
]
