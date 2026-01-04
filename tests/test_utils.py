"""Tests for utility functions"""


class TestExtractDomain:
    """Test extract_domain utility function."""

    def test_returns_provided_domain(self):
        """Test returns provided domain when given."""
        from hackles.core.utils import extract_domain

        result = extract_domain([], domain="CORP.LOCAL")
        assert result == "CORP.LOCAL"

    def test_returns_provided_domain_over_results(self):
        """Test provided domain takes precedence over results."""
        from hackles.core.utils import extract_domain

        results = [{"name": "USER@OTHER.COM"}]
        result = extract_domain(results, domain="CORP.LOCAL")
        assert result == "CORP.LOCAL"

    def test_returns_none_for_empty_results(self):
        """Test returns None when results are empty and no domain provided."""
        from hackles.core.utils import extract_domain

        result = extract_domain([])
        assert result is None

    def test_returns_none_for_none_results(self):
        """Test returns None when results are None-ish."""
        from hackles.core.utils import extract_domain

        result = extract_domain(None, domain=None)
        assert result is None

    def test_extracts_from_name_field(self):
        """Test extracts domain from 'name' field."""
        from hackles.core.utils import extract_domain

        results = [{"name": "ADMIN@CORP.LOCAL"}]
        result = extract_domain(results)
        assert result == "CORP.LOCAL"

    def test_extracts_from_principal_field(self):
        """Test extracts domain from 'principal' field."""
        from hackles.core.utils import extract_domain

        results = [{"principal": "SVC_ACCOUNT@DOMAIN.COM"}]
        result = extract_domain(results)
        assert result == "DOMAIN.COM"

    def test_extracts_from_user_field(self):
        """Test extracts domain from 'user' field."""
        from hackles.core.utils import extract_domain

        results = [{"user": "JOHN.DOE@EXAMPLE.ORG"}]
        result = extract_domain(results)
        assert result == "EXAMPLE.ORG"

    def test_extracts_from_computer_field(self):
        """Test extracts domain from 'computer' field."""
        from hackles.core.utils import extract_domain

        results = [{"computer": "DC01@CORP.LOCAL"}]
        result = extract_domain(results)
        assert result == "CORP.LOCAL"

    def test_extracts_from_target_field(self):
        """Test extracts domain from 'target' field."""
        from hackles.core.utils import extract_domain

        results = [{"target": "SERVER01@INTERNAL.NET"}]
        result = extract_domain(results)
        assert result == "INTERNAL.NET"

    def test_field_priority_order(self):
        """Test fields are checked in priority order (name first)."""
        from hackles.core.utils import extract_domain

        # 'name' should be checked before 'principal'
        results = [{"name": "USER@FIRST.COM", "principal": "USER@SECOND.COM"}]
        result = extract_domain(results)
        assert result == "FIRST.COM"

    def test_skips_empty_fields(self):
        """Test skips empty/None fields."""
        from hackles.core.utils import extract_domain

        results = [{"name": "", "principal": None, "user": "ADMIN@FOUND.COM"}]
        result = extract_domain(results)
        assert result == "FOUND.COM"

    def test_skips_fields_without_at_symbol(self):
        """Test skips fields that don't contain @ symbol."""
        from hackles.core.utils import extract_domain

        results = [{"name": "LOCALUSER", "user": "VALID@DOMAIN.COM"}]
        result = extract_domain(results)
        assert result == "DOMAIN.COM"

    def test_returns_none_when_no_valid_domain_found(self):
        """Test returns None when no field contains a domain."""
        from hackles.core.utils import extract_domain

        results = [{"name": "LOCALUSER", "other_field": "value"}]
        result = extract_domain(results)
        assert result is None

    def test_uses_first_result_with_domain(self):
        """Test uses first result that has a valid domain."""
        from hackles.core.utils import extract_domain

        results = [{"name": "LOCALUSER"}, {"name": "USER@FIRST.COM"}, {"name": "USER@SECOND.COM"}]
        result = extract_domain(results)
        assert result == "FIRST.COM"

    def test_handles_complex_domain_names(self):
        """Test handles complex/nested domain names."""
        from hackles.core.utils import extract_domain

        results = [{"name": "USER@SUB.DOMAIN.CORP.LOCAL"}]
        result = extract_domain(results)
        assert result == "SUB.DOMAIN.CORP.LOCAL"

    def test_handles_email_like_names(self):
        """Test handles email-like principal names."""
        from hackles.core.utils import extract_domain

        results = [{"name": "john.doe@company.com"}]
        result = extract_domain(results)
        assert result == "company.com"

    def test_multiple_at_symbols(self):
        """Test extracts domain after last @ symbol."""
        from hackles.core.utils import extract_domain

        # Edge case: multiple @ (shouldn't happen but test anyway)
        results = [{"name": "weird@name@DOMAIN.COM"}]
        result = extract_domain(results)
        assert result == "DOMAIN.COM"

    def test_case_preservation(self):
        """Test domain case is preserved."""
        from hackles.core.utils import extract_domain

        results = [{"name": "user@MixedCase.Domain.COM"}]
        result = extract_domain(results)
        assert result == "MixedCase.Domain.COM"


class TestExtractDomainEdgeCases:
    """Test extract_domain edge cases."""

    def test_empty_dict_in_results(self):
        """Test handles empty dicts in results."""
        from hackles.core.utils import extract_domain

        results = [{}, {"name": "USER@FOUND.COM"}]
        result = extract_domain(results)
        assert result == "FOUND.COM"

    def test_mixed_valid_invalid_results(self):
        """Test handles mix of valid and invalid results."""
        from hackles.core.utils import extract_domain

        results = [{"irrelevant": "data"}, {"name": ""}, {"name": "USER@VALID.COM"}]  # Empty string
        result = extract_domain(results)
        assert result == "VALID.COM"

    def test_at_symbol_only(self):
        """Test handles string with only @ symbol."""
        from hackles.core.utils import extract_domain

        results = [{"name": "@"}]
        result = extract_domain(results)
        # Should return empty string after @
        assert result == ""

    def test_at_symbol_at_end(self):
        """Test handles @ at end of string."""
        from hackles.core.utils import extract_domain

        results = [{"name": "USER@"}]
        result = extract_domain(results)
        assert result == ""

    def test_whitespace_in_domain(self):
        """Test preserves whitespace (unusual but possible)."""
        from hackles.core.utils import extract_domain

        results = [{"name": "USER@ DOMAIN.COM"}]
        result = extract_domain(results)
        assert result == " DOMAIN.COM"
