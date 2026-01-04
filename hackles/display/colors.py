"""ANSI color codes and severity levels for terminal output"""

from enum import Enum


def _no_color() -> bool:
    """Check if color output is disabled (lazy import to avoid circular deps)."""
    from hackles.core.config import config

    return config.no_color


class Colors:
    """ANSI color codes for terminal output with no-color support"""

    _HEADER = "\033[95m"
    _BLUE = "\033[94m"
    _CYAN = "\033[96m"
    _GREEN = "\033[92m"
    _WARNING = "\033[93m"
    _FAIL = "\033[91m"
    _END = "\033[0m"
    _BOLD = "\033[1m"
    _WHITE = "\033[97m"
    _GRAY = "\033[90m"

    @classmethod
    def _c(cls, code: str) -> str:
        """Return color code if colors enabled, empty string otherwise."""
        return "" if _no_color() else code

    @property
    def HEADER(self) -> str:
        return self._c(self._HEADER)

    @property
    def BLUE(self) -> str:
        return self._c(self._BLUE)

    @property
    def CYAN(self) -> str:
        return self._c(self._CYAN)

    @property
    def GREEN(self) -> str:
        return self._c(self._GREEN)

    @property
    def WARNING(self) -> str:
        return self._c(self._WARNING)

    @property
    def FAIL(self) -> str:
        return self._c(self._FAIL)

    @property
    def END(self) -> str:
        return self._c(self._END)

    @property
    def BOLD(self) -> str:
        return self._c(self._BOLD)

    @property
    def WHITE(self) -> str:
        return self._c(self._WHITE)

    @property
    def GRAY(self) -> str:
        return self._c(self._GRAY)


# Singleton instance for property access
colors = Colors()


class Severity(Enum):
    """Severity levels for findings with associated colors (LinPEAS-style)"""

    CRITICAL = ("CRITICAL", "\033[91m\033[1m")  # Bold Red - immediate exploitation
    HIGH = ("HIGH", "\033[91m")  # Red - serious risk
    MEDIUM = ("MEDIUM", "\033[38;5;208m")  # Orange - concerning misconfiguration
    LOW = ("LOW", "\033[93m")  # Yellow - informational/hardening
    INFO = ("INFO", "\033[90m")  # Gray - metadata/statistics

    @property
    def label(self):
        return self.value[0]

    @property
    def color(self):
        """Return color code if colors enabled, empty string otherwise."""
        return "" if _no_color() else self.value[1]
