"""Row limit enforcement for SQL queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlglot import exp

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


@dataclass(frozen=True)
class LimitCheckResult:
    """Result of checking row limits on a query.

    Attributes:
        has_limit: Whether the query has a LIMIT clause.
        limit_value: The LIMIT value if present, None otherwise.
        exceeds_max: Whether the limit exceeds the configured maximum.
        reason: Explanation if the check failed.
    """

    has_limit: bool
    limit_value: int | None = None
    exceeds_max: bool = False
    reason: str | None = None

    @property
    def is_ok(self) -> bool:
        """Returns True if the limit check passed."""
        return self.reason is None


class LimitEnforcer:
    """Enforces row limits on SELECT queries.

    Can be configured to:
    - Require LIMIT on all SELECT queries
    - Enforce a maximum LIMIT value
    - Auto-inject LIMIT into queries (via rewriting)
    """

    def __init__(
        self,
        max_rows: int | None = None,
        require_limit: bool = False,
    ) -> None:
        """Initialize the limit enforcer.

        Args:
            max_rows: Maximum allowed LIMIT value. If set, queries with
                      LIMIT > max_rows will be rejected.
            require_limit: If True, SELECT queries without LIMIT are rejected.
        """
        self.max_rows = max_rows
        self.require_limit = require_limit

    def check(self, expr: Expression) -> LimitCheckResult:
        """Check if an expression satisfies limit requirements.

        Only applies to SELECT statements. Non-SELECT statements always pass.

        Args:
            expr: The parsed SQL expression.

        Returns:
            LimitCheckResult indicating whether the query is acceptable.
        """
        # Only check SELECT statements
        if not isinstance(expr, exp.Select):
            return LimitCheckResult(has_limit=False)

        # Extract LIMIT value
        limit_clause = expr.args.get("limit")
        if limit_clause is None:
            if self.require_limit:
                return LimitCheckResult(
                    has_limit=False,
                    reason="SELECT query requires a LIMIT clause",
                )
            return LimitCheckResult(has_limit=False)

        # Parse the limit value
        limit_value = self._extract_limit_value(limit_clause)

        if limit_value is None:
            # Complex limit expression (e.g., variable) - can't validate statically
            return LimitCheckResult(has_limit=True, limit_value=None)

        # Check against max_rows
        if self.max_rows is not None and limit_value > self.max_rows:
            return LimitCheckResult(
                has_limit=True,
                limit_value=limit_value,
                exceeds_max=True,
                reason=f"LIMIT {limit_value} exceeds maximum allowed ({self.max_rows})",
            )

        return LimitCheckResult(
            has_limit=True,
            limit_value=limit_value,
        )

    def _extract_limit_value(self, limit_clause: Expression) -> int | None:
        """Extract numeric limit value from LIMIT clause.

        Args:
            limit_clause: The LIMIT expression.

        Returns:
            The limit value as int, or None if it can't be determined.
        """
        # Handle Limit expression
        if isinstance(limit_clause, exp.Limit):
            limit_expr = limit_clause.expression
            if isinstance(limit_expr, exp.Literal) and limit_expr.is_int:
                return int(limit_expr.this)
        # Handle direct literal
        elif isinstance(limit_clause, exp.Literal) and limit_clause.is_int:
            return int(limit_clause.this)

        return None

    def add_limit(self, expr: Expression, limit: int | None = None) -> Expression:
        """Add or replace LIMIT clause on a SELECT expression.

        Args:
            expr: The parsed SQL expression.
            limit: The limit value to set. Uses max_rows if not specified.

        Returns:
            Modified expression with LIMIT clause.

        Note:
            Returns the original expression if not a SELECT or no limit specified.
        """
        if not isinstance(expr, exp.Select):
            return expr

        limit_val = limit or self.max_rows
        if limit_val is None:
            return expr

        # Clone the expression to avoid mutating the original
        new_expr = expr.copy()

        # Add or replace LIMIT
        new_expr.set("limit", exp.Limit(expression=exp.Literal.number(limit_val)))

        return new_expr
