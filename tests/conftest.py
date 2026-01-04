"""Pytest fixtures for hackles tests"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_bh():
    """Mock BloodHoundCE instance for testing queries."""
    bh = MagicMock()
    bh.run_query.return_value = []
    bh._accumulated_results = []
    bh.accumulated_results = []
    bh.clear_results_cache = MagicMock()
    return bh


@pytest.fixture
def mock_bh_with_results():
    """Mock BloodHoundCE instance that returns sample results."""
    bh = MagicMock()
    bh._accumulated_results = []
    bh.accumulated_results = []
    bh.clear_results_cache = MagicMock()

    def mock_query(query, params=None):
        # Return sample results based on query content
        if "User" in query and "hasspn" in query:
            return [{"name": "SVC_TEST@DOMAIN.COM", "enabled": True, "admincount": False}]
        elif "Computer" in query:
            return [{"name": "WS01.DOMAIN.COM", "os": "Windows 10", "enabled": True}]
        elif "Group" in query:
            return [{"name": "DOMAIN ADMINS@DOMAIN.COM", "objectid": "S-1-5-21-xxx-512"}]
        return []

    bh.run_query = mock_query
    return bh


@pytest.fixture
def sample_user_results():
    """Sample user query results."""
    return [
        {"name": "ADMIN@DOMAIN.COM", "enabled": True, "admincount": True},
        {"name": "USER1@DOMAIN.COM", "enabled": True, "admincount": False},
        {"name": "SVC_ACCOUNT@DOMAIN.COM", "enabled": True, "hasspn": True},
    ]


@pytest.fixture
def sample_computer_results():
    """Sample computer query results."""
    return [
        {"name": "DC01.DOMAIN.COM", "os": "Windows Server 2019", "enabled": True},
        {"name": "WS01.DOMAIN.COM", "os": "Windows 10", "enabled": True, "haslaps": False},
        {"name": "SRV01.DOMAIN.COM", "os": "Windows Server 2016", "enabled": True},
    ]


@pytest.fixture
def sample_path_results():
    """Sample path finding results."""
    return [
        {
            "nodes": ["USER@DOMAIN.COM", "GROUP@DOMAIN.COM", "DC01.DOMAIN.COM"],
            "node_types": ["User", "Group", "Computer"],
            "relationships": ["MemberOf", "AdminTo"],
            "path_length": 2,
        }
    ]


@pytest.fixture
def mock_config():
    """Mock config module for testing."""
    with patch("hackles.core.config.config") as mock:
        mock.quiet_mode = False
        mock.show_abuse = False
        mock.debug_mode = False
        mock.no_color = True
        mock.output_format = "table"
        mock.owned_cache = {}
        mock.severity_filter = None
        mock.show_progress = False
        yield mock
