"""Tests for the ProxQL validator."""

import pytest

import proxql
from proxql import ValidationResult, Validator


class TestSimpleAPI:
    """Test the simple proxql.validate() API."""

    def test_allows_select(self) -> None:
        result = proxql.validate("SELECT * FROM users")
        assert result.is_safe is True
        assert result.statement_type == "SELECT"
        assert "users" in result.tables

    def test_blocks_drop_table(self) -> None:
        result = proxql.validate("DROP TABLE users")
        assert result.is_safe is False
        assert "DROP" in (result.reason or "")

    def test_blocks_delete(self) -> None:
        result = proxql.validate("DELETE FROM users WHERE id = 1")
        assert result.is_safe is False
        assert "DELETE" in (result.reason or "")

    def test_blocks_insert(self) -> None:
        result = proxql.validate("INSERT INTO users (name) VALUES ('test')")
        assert result.is_safe is False
        assert "INSERT" in (result.reason or "")

    def test_blocks_update(self) -> None:
        result = proxql.validate("UPDATE users SET name = 'test' WHERE id = 1")
        assert result.is_safe is False
        assert "UPDATE" in (result.reason or "")


class TestReadOnlyMode:
    """Test read_only mode behavior."""

    @pytest.fixture
    def validator(self) -> Validator:
        return Validator(mode="read_only")

    def test_allows_simple_select(self, validator: Validator) -> None:
        result = validator.validate("SELECT * FROM products")
        assert result.is_safe is True

    def test_allows_select_with_join(self, validator: Validator) -> None:
        result = validator.validate(
            "SELECT * FROM products p JOIN categories c ON p.category_id = c.id"
        )
        assert result.is_safe is True
        assert "products" in result.tables
        assert "categories" in result.tables

    def test_allows_select_with_subquery(self, validator: Validator) -> None:
        result = validator.validate(
            "SELECT * FROM (SELECT id, name FROM users) AS t"
        )
        assert result.is_safe is True

    def test_allows_select_with_cte(self, validator: Validator) -> None:
        result = validator.validate("""
            WITH active_users AS (SELECT * FROM users WHERE active = true)
            SELECT * FROM active_users
        """)
        assert result.is_safe is True

    def test_blocks_truncate(self, validator: Validator) -> None:
        result = validator.validate("TRUNCATE TABLE users")
        assert result.is_safe is False


class TestWriteSafeMode:
    """Test write_safe mode behavior."""

    @pytest.fixture
    def validator(self) -> Validator:
        return Validator(mode="write_safe")

    def test_allows_select(self, validator: Validator) -> None:
        result = validator.validate("SELECT * FROM users")
        assert result.is_safe is True

    def test_allows_insert(self, validator: Validator) -> None:
        result = validator.validate("INSERT INTO users (name) VALUES ('test')")
        assert result.is_safe is True

    def test_allows_update(self, validator: Validator) -> None:
        result = validator.validate("UPDATE users SET name = 'test' WHERE id = 1")
        assert result.is_safe is True

    def test_blocks_delete(self, validator: Validator) -> None:
        result = validator.validate("DELETE FROM users WHERE id = 1")
        assert result.is_safe is False

    def test_blocks_drop(self, validator: Validator) -> None:
        result = validator.validate("DROP TABLE users")
        assert result.is_safe is False

    def test_blocks_truncate(self, validator: Validator) -> None:
        result = validator.validate("TRUNCATE TABLE users")
        assert result.is_safe is False


class TestTableAllowlist:
    """Test table allowlist functionality."""

    @pytest.fixture
    def validator(self) -> Validator:
        return Validator(
            mode="read_only",
            allowed_tables=["products", "categories"],
        )

    def test_allows_whitelisted_table(self, validator: Validator) -> None:
        result = validator.validate("SELECT * FROM products")
        assert result.is_safe is True

    def test_blocks_non_whitelisted_table(self, validator: Validator) -> None:
        result = validator.validate("SELECT * FROM users")
        assert result.is_safe is False
        assert "users" in (result.reason or "")

    def test_blocks_mixed_tables(self, validator: Validator) -> None:
        """If any table is not allowed, block the query."""
        result = validator.validate(
            "SELECT * FROM products JOIN users ON products.user_id = users.id"
        )
        assert result.is_safe is False

    def test_case_insensitive(self, validator: Validator) -> None:
        """Table names should be case-insensitive."""
        result = validator.validate("SELECT * FROM PRODUCTS")
        assert result.is_safe is True


class TestMultiStatement:
    """Test multi-statement query handling."""

    @pytest.fixture
    def validator(self) -> Validator:
        return Validator(mode="read_only")

    def test_blocks_if_any_unsafe(self, validator: Validator) -> None:
        result = validator.validate("SELECT 1; DROP TABLE users;")
        assert result.is_safe is False


class TestParseErrors:
    """Test handling of malformed SQL."""

    @pytest.fixture
    def validator(self) -> Validator:
        return Validator(mode="read_only")

    def test_blocks_malformed_sql(self, validator: Validator) -> None:
        result = validator.validate("SELEC * FORM users")
        assert result.is_safe is False
        assert "parse" in (result.reason or "").lower() or result.reason is not None

    def test_blocks_empty_query(self, validator: Validator) -> None:
        result = validator.validate("")
        assert result.is_safe is False

    def test_blocks_whitespace_only(self, validator: Validator) -> None:
        result = validator.validate("   \n\t  ")
        assert result.is_safe is False


class TestValidationResult:
    """Test ValidationResult behavior."""

    def test_bool_conversion(self) -> None:
        safe = ValidationResult(is_safe=True)
        unsafe = ValidationResult(is_safe=False, reason="blocked")

        assert bool(safe) is True
        assert bool(unsafe) is False

    def test_can_use_in_if(self) -> None:
        result = proxql.validate("SELECT 1")
        # Intentionally using if/else to test bool conversion in control flow
        if result:  # noqa: SIM108
            passed = True
        else:
            passed = False
        assert passed is True

