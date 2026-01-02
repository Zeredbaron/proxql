"""Validation result types."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ValidationResult:
    """Immutable result of SQL validation.

    Attributes:
        is_safe: Whether the query passed all validation checks.
        reason: Human-readable explanation if blocked (None if safe).
        statement_type: The type of SQL statement (SELECT, INSERT, DROP, etc.).
        tables: List of table names referenced in the query.
    """

    is_safe: bool
    reason: str | None = None
    statement_type: str | None = None
    tables: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """Allow using result directly in boolean context."""
        return self.is_safe
