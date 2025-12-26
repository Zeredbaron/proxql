"""ProxQL - SQL validation library for blocking destructive queries.

ProxQL is a lightweight library that intercepts and validates SQL queries
before they reach your database. Perfect for AI agents that generate SQL.

Quick Start:
    >>> import proxql

    # Simple validation (read_only mode by default)
    >>> proxql.validate("SELECT * FROM users").is_safe
    True
    >>> proxql.validate("DROP TABLE users").is_safe
    False

    # Quick boolean check
    >>> proxql.is_safe("SELECT * FROM users")
    True

    # With custom configuration
    >>> from proxql import Validator
    >>> v = Validator(mode="read_only", allowed_tables=["products"])
    >>> v.validate("SELECT * FROM products").is_safe
    True
    >>> v.validate("SELECT * FROM users").is_safe
    False

Modes:
    - read_only: Only SELECT statements allowed (default)
    - write_safe: SELECT, INSERT, UPDATE allowed (no destructive ops)
    - custom: Define your own allowed/blocked statement types

For more details, see: https://github.com/zeredbaron/proxql
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import ConfigurationError, ParseError, ProxQLError
from .policy import Mode
from .result import ValidationResult
from .validator import Validator

if TYPE_CHECKING:
    from collections.abc import Sequence

__version__ = "0.1.0"
__all__ = [
    # Main API
    "validate",
    "is_safe",
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


def validate(
    sql: str,
    *,
    mode: Mode | str = Mode.READ_ONLY,
    allowed_tables: Sequence[str] | None = None,
    dialect: str | None = None,
) -> ValidationResult:
    """Validate a SQL query.

    This is the simplest way to use ProxQL. For repeated validations with the
    same configuration, create a Validator instance for better performance.

    Args:
        sql: The SQL query string to validate.
        mode: Validation mode - "read_only" (default), "write_safe", or "custom".
        allowed_tables: Optional list of table names that can be accessed.
            If set, queries referencing other tables will be blocked.
        dialect: SQL dialect for parsing (e.g., 'postgres', 'mysql', 'snowflake').
            If None, sqlglot will auto-detect.

    Returns:
        ValidationResult with is_safe=True if query passes all checks,
        or is_safe=False with a reason explaining why it was blocked.

    Examples:
        >>> import proxql

        # Basic validation (blocks all non-SELECT)
        >>> proxql.validate("SELECT * FROM users").is_safe
        True
        >>> proxql.validate("DROP TABLE users").is_safe
        False

        # Allow writes
        >>> proxql.validate("INSERT INTO logs VALUES (1)", mode="write_safe").is_safe
        True

        # Restrict to specific tables
        >>> proxql.validate(
        ...     "SELECT * FROM users",
        ...     allowed_tables=["products", "categories"]
        ... ).is_safe
        False
    """
    # Use default validator for simple read_only case (optimization)
    if mode == Mode.READ_ONLY and allowed_tables is None and dialect is None:
        return _default_validator.validate(sql)

    # Create a one-off validator for custom configuration
    validator = Validator(
        mode=mode,
        allowed_tables=list(allowed_tables) if allowed_tables else None,
        dialect=dialect,
    )
    return validator.validate(sql)


def is_safe(
    sql: str,
    *,
    mode: Mode | str = Mode.READ_ONLY,
    allowed_tables: Sequence[str] | None = None,
    dialect: str | None = None,
) -> bool:
    """Check if a SQL query is safe (convenience wrapper).

    This is a shorthand for `validate(sql).is_safe`. Use this when you only
    need a boolean result and don't need the detailed ValidationResult.

    Args:
        sql: The SQL query string to validate.
        mode: Validation mode - "read_only" (default), "write_safe", or "custom".
        allowed_tables: Optional list of table names that can be accessed.
        dialect: SQL dialect for parsing.

    Returns:
        True if the query passes all validation checks, False otherwise.

    Examples:
        >>> import proxql
        >>> proxql.is_safe("SELECT * FROM users")
        True
        >>> proxql.is_safe("DROP TABLE users")
        False

        # Use in conditionals
        >>> if proxql.is_safe(user_query):
        ...     execute_query(user_query)
        ... else:
        ...     raise SecurityError("Query blocked")
    """
    return validate(sql, mode=mode, allowed_tables=allowed_tables, dialect=dialect).is_safe
