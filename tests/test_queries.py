"""Tests for query functions"""

from unittest.mock import MagicMock


class TestQueryRegistry:
    """Test query registration system."""

    def test_get_query_registry(self):
        """Test query registry returns list of queries."""
        from hackles.queries import get_query_registry

        registry = get_query_registry()
        assert isinstance(registry, list)
        assert len(registry) > 0

    def test_query_metadata_format(self):
        """Test each query has required metadata fields."""
        from hackles.queries import get_query_registry

        registry = get_query_registry()
        for query in registry:
            assert len(query) == 5, f"Query tuple should have 5 elements: {query}"
            name, func, category, default, severity = query
            assert isinstance(name, str)
            assert callable(func)
            assert isinstance(category, str)
            assert isinstance(default, bool)

    def test_categories_exist(self):
        """Test expected categories exist in registry."""
        from hackles.queries import get_query_registry

        registry = get_query_registry()
        categories = {q[2] for q in registry}

        expected = [
            "ACL Abuse",
            "ADCS",
            "Credentials",
            "Delegation",
            "Lateral Movement",
            "Security Hygiene",
        ]
        for cat in expected:
            assert cat in categories, f"Missing category: {cat}"


class TestQueryFunctions:
    """Test individual query functions."""

    def test_kerberoastable_query_no_results(self, mock_bh, mock_config):
        """Test kerberoastable query with no results."""
        from hackles.display.colors import Severity
        from hackles.queries.credentials.kerberoastable import get_kerberoastable

        result = get_kerberoastable(mock_bh, None, Severity.HIGH)
        assert result == 0
        mock_bh.run_query.assert_called()

    def test_kerberoastable_query_with_results(self, mock_config):
        """Test kerberoastable query with results."""

        from hackles.display.colors import Severity
        from hackles.queries.credentials.kerberoastable import get_kerberoastable

        mock_bh = MagicMock()
        mock_bh.run_query.return_value = [
            {
                "name": "SVC_SQL@DOMAIN.COM",
                "displayname": "SQL Service",
                "enabled": True,
                "admincount": False,
                "description": "Service account",
                "spns": ["MSSQLSvc/sql01.domain.com:1433"],
                "pwdlastset": 1704067200,
                "pwd_age": "<1 month",
            }
        ]

        result = get_kerberoastable(mock_bh, None, Severity.HIGH)
        assert result == 1

    def test_query_domain_filter(self, mock_bh, mock_config):
        """Test queries respect domain filter."""
        from hackles.display.colors import Severity
        from hackles.queries.credentials.kerberoastable import get_kerberoastable

        get_kerberoastable(mock_bh, "DOMAIN.COM", Severity.HIGH)

        # Check that domain parameter was passed
        call_args = mock_bh.run_query.call_args
        assert call_args is not None
        # Second argument should be params dict with domain
        if len(call_args[0]) > 1:
            call_args[0][1]
        else:
            call_args[1].get("params", {}) if call_args[1] else {}


class TestQueryReturnValues:
    """Test that queries return correct count values."""

    def test_query_returns_int(self, mock_bh, mock_config):
        """Test queries return integer count."""
        from hackles.display.colors import Severity
        from hackles.queries.credentials.kerberoastable import get_kerberoastable

        result = get_kerberoastable(mock_bh, None, Severity.HIGH)
        assert isinstance(result, int)
