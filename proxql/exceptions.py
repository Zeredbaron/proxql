"""ProxQL custom exceptions."""


class ProxQLError(Exception):
    """Base exception for all ProxQL errors."""

    pass


class ParseError(ProxQLError):
    """Raised when SQL parsing fails."""

    def __init__(self, message: str, sql: str | None = None) -> None:
        self.sql = sql
        super().__init__(message)


class ConfigurationError(ProxQLError):
    """Raised when validator configuration is invalid."""

    pass
