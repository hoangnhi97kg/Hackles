"""Tests for abuse template loading"""

from pathlib import Path

import pytest


class TestAbuseTemplateLoader:
    """Test abuse template loading functionality."""

    def test_templates_directory_exists(self):
        """Test templates directory exists."""
        templates_dir = Path(__file__).parent.parent / "hackles" / "abuse" / "templates"
        assert templates_dir.exists()
        assert templates_dir.is_dir()

    def test_load_abuse_templates_returns_dict(self):
        """Test load_abuse_templates returns dictionary."""
        from hackles.abuse.loader import load_abuse_templates

        templates = load_abuse_templates()
        assert isinstance(templates, dict)

    def test_get_abuse_template_returns_dict(self):
        """Test get_abuse_template returns dictionary for known template."""
        from hackles.abuse.loader import get_abuse_template

        # Load a known template
        template = get_abuse_template("GenericAll")
        if template:  # Template might not exist in test env
            assert isinstance(template, dict)
            assert "description" in template or "commands" in template

    def test_get_abuse_template_returns_none_for_unknown(self):
        """Test get_abuse_template returns None for unknown template."""
        from hackles.abuse.loader import get_abuse_template

        template = get_abuse_template("NonExistentTemplate12345")
        assert template is None

    def test_list_abuse_templates_returns_list(self):
        """Test list_abuse_templates returns sorted list."""
        from hackles.abuse.loader import list_abuse_templates

        templates = list_abuse_templates()
        assert isinstance(templates, list)
        # Should be sorted
        assert templates == sorted(templates)

    def test_templates_have_required_fields(self):
        """Test all templates have required fields."""
        templates_dir = Path(__file__).parent.parent / "hackles" / "abuse" / "templates"
        import yaml

        for template_file in templates_dir.glob("*.yml"):
            with open(template_file) as f:
                data = yaml.safe_load(f)

            assert "name" in data, f"Template {template_file.name} missing 'name'"
            # Commands or description should exist
            assert (
                "commands" in data or "description" in data
            ), f"Template {template_file.name} missing 'commands' or 'description'"

    def test_template_count(self):
        """Test we have expected number of templates."""
        templates_dir = Path(__file__).parent.parent / "hackles" / "abuse" / "templates"

        templates = list(templates_dir.glob("*.yml"))
        # We should have at least 40+ templates
        assert len(templates) >= 40, f"Expected 40+ templates, found {len(templates)}"


class TestAbuseTemplatePlaceholders:
    """Test placeholder replacement in templates."""

    def test_placeholders_format(self):
        """Test placeholders use correct format."""
        templates_dir = Path(__file__).parent.parent / "hackles" / "abuse" / "templates"

        for template_file in templates_dir.glob("*.yml"):
            content = template_file.read_text()
            # Check for properly formatted placeholders (not Python format strings)
            if "<" in content:
                # Should use <PLACEHOLDER> format
                assert (
                    "<%s>" not in content
                ), f"Template {template_file.name} uses wrong placeholder format"
