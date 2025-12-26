"""ProxQL - SQL validation library for blocking destructive queries.

ProxQL is a lightweight library that intercepts and validates SQL queries
before they reach your database. Perfect for AI agents that generate SQL.

Basic usage:
    >>> import proxql
    >>> result = proxql.validate("SELECT * FROM users")
    >>> result.is_safe
    True

    >>> result = proxql.validate("DROP TABLE users")
    >>> result.is_safe
    False
    >>> result.reason
    "Statement type 'DROP' is not allowed in read_only mode"

For more control, use the Validator class:
    >>> from proxql import Validator
    >>> v = Validator(mode="read_only", allowed_tables=["products"])
    >>> v.validate("SELECT * FROM products").is_safe
    True
    >>> v.validate("SELECT * FROM users").is_safe
    False
"""

from .exceptions import ConfigurationError, ParseError, ProxQLError
from .policy import Mode
from .result import ValidationResult
from .validator import Validator

__version__ = "0.1.0"
__all__ = [
    # Main API
    "validate",
    "Validator",
    # Types
    "ValidationResult",
    "Mode",
    # Exceptions
    "ProxQLError",
    "ParseError",
    "ConfigurationError",
]

# Default validator instance for simple API
_default_validator = Validator(mode=Mode.READ_ONLY)


def validate(sql: str) -> ValidationResult:
    """Validate a SQL query using default read_only mode.

    This is the simplest way to use ProxQL. It blocks all non-SELECT
    statements by default.

    Args:
        sql: The SQL query string to validate.

    Returns:
        ValidationResult indicating if the query is safe.

    Example:
        >>> import proxql
        >>> proxql.validate("SELECT * FROM users").is_safe
        True
        >>> proxql.validate("DROP TABLE users").is_safe
        False
    """
    return _default_validator.validate(sql)

