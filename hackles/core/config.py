"""Global configuration and state management for Hackles"""

import threading
from pathlib import Path
from typing import Dict, Optional, Set


class Config:
    """Thread-safe singleton configuration class for global state.

    Uses an RLock to protect mutable state access. While hackles is primarily
    a single-threaded CLI tool, thread safety prevents issues if the code
    is ever used in a threaded context.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._owned_cache: Dict[str, bool] = {}
        self._quiet_mode: bool = False
        self._show_abuse: bool = False
        self._debug_mode: bool = False
        self._no_color: bool = False
        self._output_format: str = "table"  # table, json, csv, html
        self._severity_filter: Set[str] = set()  # Empty = all severities
        self._show_progress: bool = False
        # User input enhancements
        self._from_owned: Optional[str] = None  # Filter owned queries to specific principal
        self._abuse_vars: Dict[str, str] = {}  # User-provided abuse template variables
        self._stale_days: int = 90  # Threshold for stale accounts
        self._max_path_depth: int = 5  # Max hops in path queries
        self._max_paths: int = 25  # Max paths to return

    @property
    def owned_cache(self) -> Dict[str, bool]:
        """Get the owned principals cache (thread-safe read)."""
        with self._lock:
            return self._owned_cache

    @owned_cache.setter
    def owned_cache(self, value: Dict[str, bool]) -> None:
        """Set the owned principals cache (thread-safe write)."""
        with self._lock:
            self._owned_cache = value

    @property
    def quiet_mode(self) -> bool:
        with self._lock:
            return self._quiet_mode

    @quiet_mode.setter
    def quiet_mode(self, value: bool) -> None:
        with self._lock:
            self._quiet_mode = value

    @property
    def show_abuse(self) -> bool:
        with self._lock:
            return self._show_abuse

    @show_abuse.setter
    def show_abuse(self, value: bool) -> None:
        with self._lock:
            self._show_abuse = value

    @property
    def debug_mode(self) -> bool:
        with self._lock:
            return self._debug_mode

    @debug_mode.setter
    def debug_mode(self, value: bool) -> None:
        with self._lock:
            self._debug_mode = value

    @property
    def no_color(self) -> bool:
        with self._lock:
            return self._no_color

    @no_color.setter
    def no_color(self, value: bool) -> None:
        with self._lock:
            self._no_color = value

    @property
    def output_format(self) -> str:
        with self._lock:
            return self._output_format

    @output_format.setter
    def output_format(self, value: str) -> None:
        with self._lock:
            self._output_format = value

    @property
    def severity_filter(self) -> Set[str]:
        with self._lock:
            return self._severity_filter

    @severity_filter.setter
    def severity_filter(self, value: Set[str]) -> None:
        with self._lock:
            self._severity_filter = value

    @property
    def show_progress(self) -> bool:
        with self._lock:
            return self._show_progress

    @show_progress.setter
    def show_progress(self, value: bool) -> None:
        with self._lock:
            self._show_progress = value

    @property
    def from_owned(self) -> Optional[str]:
        """Get the from_owned filter principal."""
        with self._lock:
            return self._from_owned

    @from_owned.setter
    def from_owned(self, value: Optional[str]) -> None:
        """Set the from_owned filter principal."""
        with self._lock:
            self._from_owned = value

    @property
    def abuse_vars(self) -> Dict[str, str]:
        """Get the abuse template variables."""
        with self._lock:
            return self._abuse_vars

    @abuse_vars.setter
    def abuse_vars(self, value: Dict[str, str]) -> None:
        """Set the abuse template variables."""
        with self._lock:
            self._abuse_vars = value

    @property
    def stale_days(self) -> int:
        """Get the stale account threshold in days."""
        with self._lock:
            return self._stale_days

    @stale_days.setter
    def stale_days(self, value: int) -> None:
        """Set the stale account threshold in days."""
        with self._lock:
            self._stale_days = value

    @property
    def max_path_depth(self) -> int:
        """Get the maximum path depth for queries."""
        with self._lock:
            return self._max_path_depth

    @max_path_depth.setter
    def max_path_depth(self, value: int) -> None:
        """Set the maximum path depth for queries."""
        with self._lock:
            self._max_path_depth = value

    @property
    def max_paths(self) -> int:
        """Get the maximum number of paths to return."""
        with self._lock:
            return self._max_paths

    @max_paths.setter
    def max_paths(self, value: int) -> None:
        """Set the maximum number of paths to return."""
        with self._lock:
            self._max_paths = value

    def load_abuse_config(self, path: Path) -> None:
        """Load abuse variables from config file (KEY=VALUE format).

        Lines starting with # are treated as comments.
        CLI --abuse-var arguments should be applied after this to allow overrides.
        """
        with self._lock:
            if path.exists():
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, value = line.split("=", 1)
                            self._abuse_vars[key.strip()] = value.strip()

    def reset(self):
        """Reset all state to defaults (thread-safe)."""
        with self._lock:
            self._owned_cache.clear()
            self._quiet_mode = False
            self._show_abuse = False
            self._debug_mode = False
            self._no_color = False
            self._output_format = "table"
            self._severity_filter = set()
            self._show_progress = False
            # Reset user input enhancements
            self._from_owned = None
            self._abuse_vars.clear()
            self._stale_days = 90
            self._max_path_depth = 5
            self._max_paths = 25


# Singleton instance
config = Config()
