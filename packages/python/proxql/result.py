"""Validation result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cost import CostEstimate


@dataclass(frozen=True)
class ValidationResult:
    """Immutable result of SQL validation.

    Attributes:
        is_safe: Whether the query passed all validation checks.
        reason: Human-readable explanation if blocked (None if safe).
        statement_type: The type of SQL statement (SELECT, INSERT, DROP, etc.).
        tables: List of table names referenced in the query.
        cost: Estimated query cost/complexity (None if cost estimation disabled).
        limit_value: The LIMIT value if present in the query.
        warnings: Non-blocking issues detected (e.g., high cost queries that passed).
    """

    is_safe: bool
    reason: str | None = None
    statement_type: str | None = None
    tables: list[str] = field(default_factory=list)
    cost: CostEstimate | None = None
    limit_value: int | None = None
    warnings: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """Allow using result directly in boolean context."""
        return self.is_safe
