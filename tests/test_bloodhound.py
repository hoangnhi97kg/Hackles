"""Tests for BloodHoundCE class"""


class TestBloodHoundCE:
    """Test BloodHoundCE class methods."""

    def test_attack_edges_constant(self):
        """Test ATTACK_EDGES constant contains expected edges."""
        from hackles.core.bloodhound import ATTACK_EDGES

        # Core edges
        assert "AdminTo" in ATTACK_EDGES
        assert "MemberOf" in ATTACK_EDGES
        assert "HasSession" in ATTACK_EDGES

        # ACL edges
        assert "GenericAll" in ATTACK_EDGES
        assert "GenericWrite" in ATTACK_EDGES
        assert "WriteDacl" in ATTACK_EDGES
        assert "WriteOwner" in ATTACK_EDGES

        # ADCS edges
        assert "Enroll" in ATTACK_EDGES
        assert "ManageCA" in ATTACK_EDGES

        # Delegation edges
        assert "AllowedToDelegate" in ATTACK_EDGES
        assert "AllowedToAct" in ATTACK_EDGES

    def test_connection_uri_parsing(self):
        """Test connection URI is stored correctly."""
        from hackles.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        assert bh.uri == "bolt://localhost:7687"
        assert bh.username == "neo4j"
        assert bh.password == "password"

    def test_debug_mode_setting(self):
        """Test debug mode is set correctly."""
        from hackles.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password", debug=True)
        assert bh.debug is True

        bh2 = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        assert bh2.debug is False

    def test_accumulated_results_property(self):
        """Test accumulated results tracking."""
        from hackles.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        assert bh.accumulated_results == []

        bh._accumulated_results = [{"test": "data"}]
        assert bh.accumulated_results == [{"test": "data"}]

    def test_clear_results_cache(self):
        """Test clearing results cache."""
        from hackles.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        bh._accumulated_results = [{"test": "data"}]
        bh.clear_results_cache()
        assert bh._accumulated_results == []


class TestCypherHelpers:
    """Test Cypher helper functions."""

    def test_node_type_function(self):
        """Test node_type() generates correct CASE expression."""
        from hackles.core.cypher import node_type

        result = node_type("n")
        assert "CASE" in result
        assert ":User" in result
        assert ":Computer" in result
        assert ":Group" in result
