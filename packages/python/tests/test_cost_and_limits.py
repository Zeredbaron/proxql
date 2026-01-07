"""Tests for cost estimation and row limit enforcement."""

import pytest

import proxql
from proxql import CostEstimate, CostEstimator, CostLevel, LimitEnforcer, Validator


class TestCostEstimation:
    """Test query cost estimation."""

    @pytest.fixture
    def estimator(self) -> CostEstimator:
        return CostEstimator()

    def test_simple_select_is_low_cost(self, estimator: CostEstimator) -> None:
        """Simple SELECT should be low cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT id, name FROM users WHERE id = 1")
        cost = estimator.estimate(stmt)

        assert cost.level == CostLevel.LOW
        assert cost.score <= 20

    def test_select_star_adds_cost(self, estimator: CostEstimator) -> None:
        """SELECT * should add to cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users")
        cost = estimator.estimate(stmt)

        assert "SELECT * (all columns)" in cost.factors

    def test_missing_where_adds_cost(self, estimator: CostEstimator) -> None:
        """SELECT without WHERE should add to cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT id FROM users")
        cost = estimator.estimate(stmt)

        assert "SELECT without WHERE clause" in cost.factors

    def test_joins_add_cost(self, estimator: CostEstimator) -> None:
        """JOINs should add to cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("""
            SELECT * FROM users u
            JOIN orders o ON u.id = o.user_id
            JOIN products p ON o.product_id = p.id
        """)
        cost = estimator.estimate(stmt)

        assert cost.level >= CostLevel.MEDIUM
        assert "2 JOIN(s)" in cost.factors

    def test_many_joins_high_cost(self, estimator: CostEstimator) -> None:
        """Many JOINs should result in high cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("""
            SELECT * FROM a
            JOIN b ON a.id = b.a_id
            JOIN c ON b.id = c.b_id
            JOIN d ON c.id = d.c_id
            JOIN e ON d.id = e.d_id
        """)
        cost = estimator.estimate(stmt)

        assert cost.level >= CostLevel.HIGH

    def test_subquery_adds_cost(self, estimator: CostEstimator) -> None:
        """Subqueries should add to cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("""
            SELECT * FROM users WHERE id IN (
                SELECT user_id FROM orders WHERE total > 100
            )
        """)
        cost = estimator.estimate(stmt)

        assert any("Subquery" in f for f in cost.factors)

    def test_order_without_limit_adds_cost(self, estimator: CostEstimator) -> None:
        """ORDER BY without LIMIT should add to cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users ORDER BY created_at")
        cost = estimator.estimate(stmt)

        assert "ORDER BY without LIMIT" in cost.factors

    def test_order_with_limit_no_penalty(self, estimator: CostEstimator) -> None:
        """ORDER BY with LIMIT should not add penalty."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users ORDER BY created_at LIMIT 10")
        cost = estimator.estimate(stmt)

        assert "ORDER BY without LIMIT" not in cost.factors

    def test_union_adds_cost(self, estimator: CostEstimator) -> None:
        """UNION should add to cost."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("""
            SELECT id FROM users
            UNION
            SELECT id FROM admins
        """)
        cost = estimator.estimate(stmt)

        assert any("UNION" in f for f in cost.factors)

    def test_cost_estimate_bool(self) -> None:
        """CostEstimate should be truthy for acceptable costs."""
        low = CostEstimate(level=CostLevel.LOW, score=10, factors=())
        medium = CostEstimate(level=CostLevel.MEDIUM, score=30, factors=())
        high = CostEstimate(level=CostLevel.HIGH, score=80, factors=())

        assert bool(low) is True
        assert bool(medium) is True
        assert bool(high) is False


class TestCostInValidator:
    """Test cost estimation integrated with Validator."""

    def test_estimate_cost_returns_cost(self) -> None:
        """Validator with estimate_cost=True should return cost info."""
        validator = Validator(mode="read_only", estimate_cost=True)
        result = validator.validate("SELECT * FROM users")

        assert result.is_safe is True
        assert result.cost is not None
        assert isinstance(result.cost.level, CostLevel)

    def test_block_high_cost(self) -> None:
        """Validator with block_high_cost=True should block expensive queries."""
        validator = Validator(mode="read_only", block_high_cost=True)

        # Simple query should pass
        result = validator.validate("SELECT id FROM users WHERE id = 1 LIMIT 10")
        assert result.is_safe is True

        # Complex query should fail
        result = validator.validate("""
            SELECT * FROM a
            JOIN b ON a.id = b.a_id
            JOIN c ON b.id = c.b_id
            JOIN d ON c.id = d.c_id
            JOIN e ON d.id = e.d_id
            ORDER BY a.created_at
        """)
        assert result.is_safe is False
        assert "cost" in (result.reason or "").lower()

    def test_max_cost_level_string(self) -> None:
        """max_cost_level should accept string."""
        validator = Validator(mode="read_only", max_cost_level="LOW")

        # Even moderate queries should fail
        result = validator.validate("SELECT * FROM users")
        assert result.is_safe is False

    def test_max_cost_level_enum(self) -> None:
        """max_cost_level should accept CostLevel enum."""
        validator = Validator(mode="read_only", max_cost_level=CostLevel.MEDIUM)

        # Simple query should pass
        result = validator.validate("SELECT id FROM users WHERE id = 1")
        assert result.is_safe is True

    def test_warnings_for_high_cost(self) -> None:
        """High cost queries should generate warnings if not blocked."""
        validator = Validator(mode="read_only", estimate_cost=True)

        result = validator.validate("""
            SELECT * FROM a
            JOIN b ON a.id = b.a_id
            JOIN c ON b.id = c.b_id
            JOIN d ON c.id = d.c_id
            JOIN e ON d.id = e.d_id
        """)

        # Should pass but with warnings
        assert result.is_safe is True
        assert len(result.warnings) > 0
        assert any("cost" in w.lower() for w in result.warnings)


class TestLimitEnforcement:
    """Test row limit enforcement."""

    @pytest.fixture
    def enforcer(self) -> LimitEnforcer:
        return LimitEnforcer(max_rows=1000, require_limit=False)

    def test_query_with_valid_limit(self, enforcer: LimitEnforcer) -> None:
        """Query with limit under max should pass."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users LIMIT 100")
        result = enforcer.check(stmt)

        assert result.is_ok is True
        assert result.limit_value == 100

    def test_query_exceeds_max_rows(self, enforcer: LimitEnforcer) -> None:
        """Query with limit over max should fail."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users LIMIT 5000")
        result = enforcer.check(stmt)

        assert result.is_ok is False
        assert result.exceeds_max is True
        assert "5000" in (result.reason or "")

    def test_query_without_limit_no_require(self, enforcer: LimitEnforcer) -> None:
        """Query without LIMIT should pass if not required."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users")
        result = enforcer.check(stmt)

        assert result.is_ok is True
        assert result.has_limit is False

    def test_query_without_limit_required(self) -> None:
        """Query without LIMIT should fail if required."""
        enforcer = LimitEnforcer(require_limit=True)
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("SELECT * FROM users")
        result = enforcer.check(stmt)

        assert result.is_ok is False
        assert "requires a LIMIT" in (result.reason or "")

    def test_non_select_always_passes(self, enforcer: LimitEnforcer) -> None:
        """Non-SELECT statements should always pass limit check."""
        from proxql.parser import Parser

        parser = Parser()
        stmt = parser.parse_one("INSERT INTO users (name) VALUES ('test')")
        result = enforcer.check(stmt)

        assert result.is_ok is True


class TestLimitInValidator:
    """Test limit enforcement integrated with Validator."""

    def test_max_rows_blocks_excessive_limit(self) -> None:
        """Validator with max_rows should block excessive limits."""
        validator = Validator(mode="read_only", max_rows=1000)

        result = validator.validate("SELECT * FROM users LIMIT 100")
        assert result.is_safe is True
        assert result.limit_value == 100

        result = validator.validate("SELECT * FROM users LIMIT 5000")
        assert result.is_safe is False
        assert "5000" in (result.reason or "")

    def test_require_limit_blocks_unlimited(self) -> None:
        """Validator with require_limit should block unlimited queries."""
        validator = Validator(mode="read_only", require_limit=True)

        result = validator.validate("SELECT * FROM users LIMIT 100")
        assert result.is_safe is True

        result = validator.validate("SELECT * FROM users")
        assert result.is_safe is False
        assert "LIMIT" in (result.reason or "")

    def test_max_rows_and_require_limit_combined(self) -> None:
        """Both max_rows and require_limit can be used together."""
        validator = Validator(mode="read_only", max_rows=1000, require_limit=True)

        # No limit - blocked
        result = validator.validate("SELECT * FROM users")
        assert result.is_safe is False

        # Limit too high - blocked
        result = validator.validate("SELECT * FROM users LIMIT 5000")
        assert result.is_safe is False

        # Valid limit - passes
        result = validator.validate("SELECT * FROM users LIMIT 500")
        assert result.is_safe is True


class TestCombinedFeatures:
    """Test cost and limit features together."""

    def test_all_features_combined(self) -> None:
        """Test validator with all new features enabled."""
        validator = Validator(
            mode="read_only",
            max_rows=1000,
            require_limit=True,
            estimate_cost=True,
            max_cost_level=CostLevel.MEDIUM,
        )

        # Good query passes
        result = validator.validate("SELECT id, name FROM users WHERE id = 1 LIMIT 10")
        assert result.is_safe is True
        assert result.cost is not None
        assert result.limit_value == 10

        # Missing limit fails
        result = validator.validate("SELECT id FROM users WHERE id = 1")
        assert result.is_safe is False

        # High cost fails
        result = validator.validate("""
            SELECT * FROM a
            JOIN b ON a.id = b.a_id
            JOIN c ON b.id = c.b_id
            JOIN d ON c.id = d.c_id
            LIMIT 10
        """)
        assert result.is_safe is False
        assert "cost" in (result.reason or "").lower()

    def test_simple_api_unchanged(self) -> None:
        """Simple API should still work without new features."""
        result = proxql.validate("SELECT * FROM users")
        assert result.is_safe is True
        assert result.cost is None  # Not enabled by default
        assert result.limit_value is None
