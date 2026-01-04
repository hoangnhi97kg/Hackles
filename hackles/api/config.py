"""API configuration management for BloodHound CE credentials.

Stores credentials in an INI file at ~/.config/hackles/hackles.ini
(respects XDG_CONFIG_HOME environment variable).
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Optional, Tuple


def get_config_dir() -> Path:
    """Get the configuration directory path, respecting XDG_CONFIG_HOME."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        return Path(xdg_config) / "hackles"
    return Path.home() / ".config" / "hackles"


def get_default_config_file() -> Path:
    """Get the default configuration file path."""
    return get_config_dir() / "hackles.ini"


class APIConfig:
    """Manage BloodHound CE API configuration.

    Stores url, token_id, and token_key in an INI file format.
    Directory is created with mode 0o700 for security.
    """

    def __init__(self, config_file: Optional[str] = None):
        """Initialize API configuration.

        Args:
            config_file: Optional path to config file. Uses default if not specified.
        """
        if config_file:
            self.config_file = Path(config_file)
        else:
            self.config_file = get_default_config_file()

        self._config = configparser.ConfigParser()
        self._load()

    def _load(self) -> None:
        """Load configuration from file."""
        # Set defaults
        self._config["DEFAULT"] = {
            "url": "",
            "token_id": "",
            "token_key": "",
        }

        if self.config_file.exists():
            self._config.read(self.config_file)

    def save(
        self,
        url: Optional[str] = None,
        token_id: Optional[str] = None,
        token_key: Optional[str] = None,
    ) -> None:
        """Save configuration to file.

        Args:
            url: BloodHound CE API URL
            token_id: API token ID
            token_key: API token secret key
        """
        # Update values if provided
        if url is not None:
            self._config["DEFAULT"]["url"] = url
        if token_id is not None:
            self._config["DEFAULT"]["token_id"] = token_id
        if token_key is not None:
            self._config["DEFAULT"]["token_key"] = token_key

        # Create directory with restrictive permissions
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.config_file.parent, 0o700)
        except OSError:
            pass  # May fail on Windows

        # Write config file with restrictive permissions from the start
        # Use umask to ensure file is created with 0o600 permissions
        old_umask = os.umask(0o077)
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                self._config.write(f)
        finally:
            os.umask(old_umask)

        # Explicitly set permissions (in case file already existed)
        try:
            os.chmod(self.config_file, 0o600)
        except OSError:
            pass  # May fail on Windows

    @property
    def url(self) -> str:
        """Get the BloodHound CE API URL."""
        return self._config["DEFAULT"].get("url", "")

    @property
    def token_id(self) -> str:
        """Get the API token ID."""
        return self._config["DEFAULT"].get("token_id", "")

    @property
    def token_key(self) -> str:
        """Get the API token secret key."""
        return self._config["DEFAULT"].get("token_key", "")

    def get_credentials(self) -> Tuple[str, str, str]:
        """Get all credentials as a tuple.

        Returns:
            Tuple of (url, token_id, token_key)
        """
        return self.url, self.token_id, self.token_key

    def has_credentials(self) -> bool:
        """Check if valid credentials are configured.

        Returns:
            True if all credentials are present and non-empty
        """
        return bool(self.url and self.token_id and self.token_key)
