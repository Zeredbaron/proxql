"""Query cost and complexity estimation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from sqlglot import exp

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class CostLevel(IntEnum):
    """Query cost levels from low to extreme."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    EXTREME = 4

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class CostEstimate:
    """Estimated cost/complexity of a query.

    Attributes:
        level: Overall cost level (LOW, MEDIUM, HIGH, EXTREME).
        score: Numeric complexity score (higher = more expensive).
        factors: List of factors contributing to the cost.
    """

    level: CostLevel
    score: int
    factors: tuple[str, ...]

    def __bool__(self) -> bool:
        """Returns True if cost is acceptable (LOW or MEDIUM)."""
        return self.level <= CostLevel.MEDIUM


class CostEstimator:
    """Estimates query cost based on structural analysis.

    This analyzes the query AST to estimate relative cost. It does NOT
    know about actual table sizes or indexes - it only looks at query
    structure to identify potentially expensive patterns.

    Cost factors:
    - Number of JOINs
    - Subquery depth
    - Cross joins / cartesian products
    - Missing WHERE clauses
    - Aggregations without GROUP BY limits
    - UNION operations
    - DISTINCT on many columns
    - ORDER BY without LIMIT
    """

    # Scoring weights for different factors
    WEIGHTS = {
        "join": 10,
        "cross_join": 50,
        "subquery": 15,
        "subquery_depth": 10,  # per level
        "no_where": 20,
        "aggregate_no_limit": 15,
        "union": 10,
        "distinct": 5,
        "order_no_limit": 15,
        "wildcard_select": 5,
        "nested_aggregate": 20,
    }

    # Thresholds for cost levels
    THRESHOLDS = {
        CostLevel.LOW: 20,
        CostLevel.MEDIUM: 50,
        CostLevel.HIGH: 100,
        # EXTREME is anything above HIGH
    }

    def estimate(self, expr: Expression) -> CostEstimate:
        """Estimate the cost of a parsed SQL expression.

        Args:
            expr: The parsed SQL expression.

        Returns:
            CostEstimate with level, score, and contributing factors.
        """
        score = 0
        factors: list[str] = []

        # Count JOINs
        join_count = self._count_joins(expr)
        if join_count > 0:
            score += join_count * self.WEIGHTS["join"]
            factors.append(f"{join_count} JOIN(s)")

        # Check for cross joins
        cross_join_count = self._count_cross_joins(expr)
        if cross_join_count > 0:
            score += cross_join_count * self.WEIGHTS["cross_join"]
            factors.append(f"{cross_join_count} CROSS JOIN(s) - cartesian product")

        # Check subquery depth
        subquery_depth = self._get_subquery_depth(expr)
        if subquery_depth > 0:
            score += self.WEIGHTS["subquery"]
            score += subquery_depth * self.WEIGHTS["subquery_depth"]
            factors.append(f"Subquery depth: {subquery_depth}")

        # Check for missing WHERE on SELECT
        if self._is_select_without_where(expr):
            score += self.WEIGHTS["no_where"]
            factors.append("SELECT without WHERE clause")

        # Check for aggregations
        if self._has_aggregate_without_limit(expr):
            score += self.WEIGHTS["aggregate_no_limit"]
            factors.append("Aggregate function without LIMIT")

        # Check for UNION
        union_count = self._count_unions(expr)
        if union_count > 0:
            score += union_count * self.WEIGHTS["union"]
            factors.append(f"{union_count} UNION operation(s)")

        # Check for DISTINCT
        if self._has_distinct(expr):
            score += self.WEIGHTS["distinct"]
            factors.append("DISTINCT clause")

        # Check for ORDER BY without LIMIT
        if self._has_order_without_limit(expr):
            score += self.WEIGHTS["order_no_limit"]
            factors.append("ORDER BY without LIMIT")

        # Check for SELECT *
        if self._has_wildcard_select(expr):
            score += self.WEIGHTS["wildcard_select"]
            factors.append("SELECT * (all columns)")

        # Determine level from score
        level = self._score_to_level(score)

        return CostEstimate(
            level=level,
            score=score,
            factors=tuple(factors),
        )

    def _score_to_level(self, score: int) -> CostLevel:
        """Convert numeric score to cost level."""
        if score <= self.THRESHOLDS[CostLevel.LOW]:
            return CostLevel.LOW
        if score <= self.THRESHOLDS[CostLevel.MEDIUM]:
            return CostLevel.MEDIUM
        if score <= self.THRESHOLDS[CostLevel.HIGH]:
            return CostLevel.HIGH
        return CostLevel.EXTREME

    def _count_joins(self, expr: Expression) -> int:
        """Count all JOIN operations."""
        return len(list(expr.find_all(exp.Join)))

    def _count_cross_joins(self, expr: Expression) -> int:
        """Count CROSS JOINs (cartesian products)."""
        count = 0
        for join in expr.find_all(exp.Join):
            kind = join.args.get("kind", "")
            is_explicit_cross = kind and "CROSS" in str(kind).upper()
            is_implicit_cross = (
                join.args.get("on") is None
                and join.args.get("using") is None
                and (not kind or kind == "")
            )
            if is_explicit_cross or is_implicit_cross:
                count += 1
        return count

    def _get_subquery_depth(self, expr: Expression, depth: int = 0) -> int:
        """Get maximum subquery nesting depth."""
        max_depth = depth
        for subquery in expr.find_all(exp.Subquery):
            # Don't recurse into subqueries we've already counted
            if subquery is not expr:
                sub_depth = self._get_subquery_depth(subquery, depth + 1)
                max_depth = max(max_depth, sub_depth)
        return max_depth

    def _is_select_without_where(self, expr: Expression) -> bool:
        """Check if this is a SELECT without WHERE clause."""
        if not isinstance(expr, exp.Select):
            return False
        # Check if there's a WHERE clause
        return expr.args.get("where") is None

    def _has_aggregate_without_limit(self, expr: Expression) -> bool:
        """Check for aggregate functions without LIMIT."""
        if not isinstance(expr, exp.Select):
            return False

        # Check if there are aggregate functions
        has_agg = any(
            isinstance(node, (exp.Count, exp.Sum, exp.Avg, exp.Min, exp.Max))
            for node in expr.find_all(exp.AggFunc)
        )

        if not has_agg:
            return False

        # Check if there's a LIMIT
        return expr.args.get("limit") is None

    def _count_unions(self, expr: Expression) -> int:
        """Count UNION operations."""
        return len(list(expr.find_all(exp.Union)))

    def _has_distinct(self, expr: Expression) -> bool:
        """Check for DISTINCT clause."""
        if isinstance(expr, exp.Select):
            return expr.args.get("distinct") is not None
        return len(list(expr.find_all(exp.Distinct))) > 0

    def _has_order_without_limit(self, expr: Expression) -> bool:
        """Check for ORDER BY without LIMIT."""
        if not isinstance(expr, exp.Select):
            return False
        has_order = expr.args.get("order") is not None
        has_limit = expr.args.get("limit") is not None
        return has_order and not has_limit

    def _has_wildcard_select(self, expr: Expression) -> bool:
        """Check for SELECT * (wildcard)."""
        for _star in expr.find_all(exp.Star):
            return True
        return False
