"""Policy engine for SQL validation rules."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from .result import ValidationResult

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class Mode(str, Enum):
    """Validation mode presets."""

    READ_ONLY = "read_only"
    WRITE_SAFE = "write_safe"
    CUSTOM = "custom"


# Statement types allowed in each mode
READ_ONLY_ALLOWED = frozenset({"SELECT", "WITH"})  # WITH for CTEs that select

WRITE_SAFE_ALLOWED = frozenset(
    {
        "SELECT",
        "WITH",
        "INSERT",
        "UPDATE",
    }
)

# Destructive statements that are always blocked in write_safe mode
# Note: sqlglot uses compound names like TRUNCATETABLE for some statements
DESTRUCTIVE_STATEMENTS = frozenset(
    {
        "DROP",
        "TRUNCATE",
        "TRUNCATETABLE",  # sqlglot uses this for TRUNCATE TABLE
        "ALTER",
        "DELETE",
        "CREATE",
        "RENAME",
        "REPLACE",
        "GRANT",
        "REVOKE",
    }
)


class PolicyEngine:
    """Applies validation policies to parsed SQL expressions.

    Attributes:
        mode: The validation mode (read_only, write_safe, custom).
        allowed_tables: Optional set of table names that can be accessed.
        allowed_statements: For custom mode, the set of allowed statement types.
        blocked_statements: For custom mode, the set of blocked statement types.
    """

    def __init__(
        self,
        mode: Mode | str = Mode.READ_ONLY,
        allowed_tables: set[str] | list[str] | None = None,
        allowed_statements: set[str] | list[str] | None = None,
        blocked_statements: set[str] | list[str] | None = None,
    ) -> None:
        """Initialize policy engine.

        Args:
            mode: Validation mode preset.
            allowed_tables: Optional whitelist of accessible tables.
            allowed_statements: For custom mode, statements to allow.
            blocked_statements: For custom mode, statements to block.
        """
        self.mode = Mode(mode) if isinstance(mode, str) else mode
        self.allowed_tables = {t.lower() for t in allowed_tables} if allowed_tables else None
        self.allowed_statements = (
            {s.upper() for s in allowed_statements} if allowed_statements else None
        )
        self.blocked_statements = (
            {s.upper() for s in blocked_statements} if blocked_statements else None
        )

    def evaluate(
        self,
        expr: Expression,
        statement_type: str,
        tables: list[str],
    ) -> ValidationResult:
        """Evaluate an expression against the configured policies.

        Args:
            expr: The parsed SQL expression.
            statement_type: The type of statement (e.g., 'SELECT').
            tables: List of tables referenced in the query.

        Returns:
            ValidationResult indicating if the query is safe.
        """
        # Check statement type against mode
        stmt_result = self._check_statement_type(statement_type)
        if not stmt_result.is_safe:
            return ValidationResult(
                is_safe=False,
                reason=stmt_result.reason,
                statement_type=statement_type,
                tables=tables,
            )

        # Check table allowlist
        if self.allowed_tables is not None:
            table_result = self._check_tables(tables)
            if not table_result.is_safe:
                return ValidationResult(
                    is_safe=False,
                    reason=table_result.reason,
                    statement_type=statement_type,
                    tables=tables,
                )

        return ValidationResult(
            is_safe=True,
            statement_type=statement_type,
            tables=tables,
        )

    def _check_statement_type(self, statement_type: str) -> ValidationResult:
        """Check if statement type is allowed by current mode."""
        stmt = statement_type.upper()

        if self.mode == Mode.READ_ONLY:
            if stmt not in READ_ONLY_ALLOWED:
                return ValidationResult(
                    is_safe=False,
                    reason=f"Statement type '{stmt}' is not allowed in read_only mode",
                )

        elif self.mode == Mode.WRITE_SAFE:
            if stmt in DESTRUCTIVE_STATEMENTS:
                return ValidationResult(
                    is_safe=False,
                    reason=f"Statement type '{stmt}' is not allowed in write_safe mode",
                )
            if stmt not in WRITE_SAFE_ALLOWED and stmt not in DESTRUCTIVE_STATEMENTS:
                # Unknown statement type - block by default
                return ValidationResult(
                    is_safe=False,
                    reason=f"Statement type '{stmt}' is not allowed in write_safe mode",
                )

        elif self.mode == Mode.CUSTOM:
            # Check blocked first (takes precedence)
            if self.blocked_statements and stmt in self.blocked_statements:
                return ValidationResult(
                    is_safe=False,
                    reason=f"Statement type '{stmt}' is blocked",
                )
            # Then check allowed
            if self.allowed_statements and stmt not in self.allowed_statements:
                return ValidationResult(
                    is_safe=False,
                    reason=f"Statement type '{stmt}' is not in allowed list",
                )

        return ValidationResult(is_safe=True)

    def _check_tables(self, tables: list[str]) -> ValidationResult:
        """Check if all tables are in the allowlist."""
        if self.allowed_tables is None:
            return ValidationResult(is_safe=True)

        for table in tables:
            if table.lower() not in self.allowed_tables:
                return ValidationResult(
                    is_safe=False,
                    reason=f"Table '{table}' is not in allowed tables list",
                )

        return ValidationResult(is_safe=True)
