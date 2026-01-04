"""Tests for configuration singleton"""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest


class TestConfigDefaults:
    """Test Config class default values."""

    def test_default_quiet_mode(self):
        """Test quiet_mode defaults to False."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.quiet_mode is False

    def test_default_show_abuse(self):
        """Test show_abuse defaults to False."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.show_abuse is False

    def test_default_debug_mode(self):
        """Test debug_mode defaults to False."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.debug_mode is False

    def test_default_no_color(self):
        """Test no_color defaults to False."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.no_color is False

    def test_default_output_format(self):
        """Test output_format defaults to 'table'."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.output_format == "table"

    def test_default_severity_filter(self):
        """Test severity_filter defaults to empty set."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.severity_filter == set()

    def test_default_show_progress(self):
        """Test show_progress defaults to False."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.show_progress is False

    def test_default_owned_cache(self):
        """Test owned_cache defaults to empty dict."""
        from hackles.core.config import Config

        cfg = Config()
        assert cfg.owned_cache == {}


class TestConfigSetters:
    """Test Config class property setters."""

    def test_set_quiet_mode(self):
        """Test setting quiet_mode."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.quiet_mode = True
        assert cfg.quiet_mode is True

    def test_set_show_abuse(self):
        """Test setting show_abuse."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.show_abuse = True
        assert cfg.show_abuse is True

    def test_set_debug_mode(self):
        """Test setting debug_mode."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.debug_mode = True
        assert cfg.debug_mode is True

    def test_set_no_color(self):
        """Test setting no_color."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.no_color = True
        assert cfg.no_color is True

    def test_set_output_format(self):
        """Test setting output_format."""
        from hackles.core.config import Config

        cfg = Config()
        for fmt in ["table", "json", "csv", "html"]:
            cfg.output_format = fmt
            assert cfg.output_format == fmt

    def test_set_severity_filter(self):
        """Test setting severity_filter."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.severity_filter = {"CRITICAL", "HIGH"}
        assert cfg.severity_filter == {"CRITICAL", "HIGH"}

    def test_set_show_progress(self):
        """Test setting show_progress."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.show_progress = True
        assert cfg.show_progress is True

    def test_set_owned_cache(self):
        """Test setting owned_cache."""
        from hackles.core.config import Config

        cfg = Config()
        cache = {"USER@DOMAIN.COM": True, "ADMIN@DOMAIN.COM": True}
        cfg.owned_cache = cache
        assert cfg.owned_cache == cache


class TestConfigReset:
    """Test Config reset functionality."""

    def test_reset_restores_defaults(self):
        """Test reset() restores all default values."""
        from hackles.core.config import Config

        cfg = Config()

        # Modify all settings
        cfg.quiet_mode = True
        cfg.show_abuse = True
        cfg.debug_mode = True
        cfg.no_color = True
        cfg.output_format = "json"
        cfg.severity_filter = {"CRITICAL"}
        cfg.show_progress = True
        cfg.owned_cache = {"USER@DOMAIN.COM": True}

        # Reset
        cfg.reset()

        # Verify defaults restored
        assert cfg.quiet_mode is False
        assert cfg.show_abuse is False
        assert cfg.debug_mode is False
        assert cfg.no_color is False
        assert cfg.output_format == "table"
        assert cfg.severity_filter == set()
        assert cfg.show_progress is False
        assert cfg.owned_cache == {}


class TestConfigSingleton:
    """Test Config singleton behavior."""

    def test_singleton_instance_exists(self):
        """Test global config instance is accessible."""
        from hackles.core.config import config

        assert config is not None

    def test_singleton_modifications_persist(self):
        """Test modifications to singleton persist."""
        from hackles.core.config import config

        original = config.quiet_mode
        config.quiet_mode = not original
        assert config.quiet_mode == (not original)

        # Reset for other tests
        config.quiet_mode = original


class TestConfigThreadSafety:
    """Test Config thread safety."""

    def test_concurrent_reads(self):
        """Test concurrent reads don't cause issues."""
        from hackles.core.config import Config

        cfg = Config()
        cfg.quiet_mode = True
        results = []

        def read_config():
            for _ in range(100):
                results.append(cfg.quiet_mode)

        threads = [threading.Thread(target=read_config) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r is True for r in results)

    def test_concurrent_writes(self):
        """Test concurrent writes don't corrupt state."""
        from hackles.core.config import Config

        cfg = Config()
        counter = {"value": 0}

        def increment_cache():
            for i in range(100):
                current = cfg.owned_cache.copy()
                current[f"USER{threading.current_thread().name}_{i}"] = True
                cfg.owned_cache = current
                counter["value"] += 1

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(increment_cache) for _ in range(5)]
            for f in futures:
                f.result()

        # Should have processed all increments without error
        assert counter["value"] == 500

    def test_concurrent_read_write(self):
        """Test concurrent reads and writes work correctly."""
        from hackles.core.config import Config

        cfg = Config()
        errors = []

        def reader():
            try:
                for _ in range(100):
                    _ = cfg.debug_mode
                    _ = cfg.output_format
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                for i in range(100):
                    cfg.debug_mode = i % 2 == 0
                    cfg.output_format = "json" if i % 2 == 0 else "table"
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=reader))
            threads.append(threading.Thread(target=writer))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors occurred: {errors}"
