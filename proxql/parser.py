"""SQL parser wrapper around sqlglot."""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError as SqlglotParseError

from .exceptions import ParseError

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class Parser:
    """SQL parser that wraps sqlglot for consistent AST handling.

    Attributes:
        dialect: The SQL dialect to use for parsing (e.g., 'postgres', 'mysql').
    """

    def __init__(self, dialect: str | None = None) -> None:
        """Initialize parser with optional dialect.

        Args:
            dialect: SQL dialect for parsing. If None, uses sqlglot's auto-detection.
        """
        self.dialect = dialect

    def parse(self, sql: str) -> list[Expression]:
        """Parse SQL string into list of AST expressions.

        Args:
            sql: The SQL string to parse.

        Returns:
            List of parsed expressions (one per statement).

        Raises:
            ParseError: If the SQL cannot be parsed.
        """
        try:
            statements = sqlglot.parse(sql, dialect=self.dialect)
            # Filter out None values (can occur with empty statements)
            return [stmt for stmt in statements if stmt is not None]
        except SqlglotParseError as e:
            raise ParseError(str(e), sql=sql) from e

    def parse_one(self, sql: str) -> Expression:
        """Parse SQL string expecting exactly one statement.

        Args:
            sql: The SQL string to parse.

        Returns:
            Single parsed expression.

        Raises:
            ParseError: If the SQL cannot be parsed or contains multiple statements.
        """
        try:
            result = sqlglot.parse_one(sql, dialect=self.dialect)
            return result
        except SqlglotParseError as e:
            raise ParseError(str(e), sql=sql) from e

    @staticmethod
    def get_statement_type(expr: Expression) -> str:
        """Extract the statement type from an expression.

        Args:
            expr: The parsed expression.

        Returns:
            Statement type as uppercase string (e.g., 'SELECT', 'DROP').
        """
        return expr.key.upper()

    @staticmethod
    def extract_tables(expr: Expression) -> list[str]:
        """Extract all table names referenced in an expression.

        This handles subqueries, CTEs, JOINs, and other nested structures.

        Args:
            expr: The parsed expression.

        Returns:
            List of table names (lowercased for consistency).
        """
        tables: list[str] = []
        for table in expr.find_all(exp.Table):
            if table.name:
                tables.append(table.name.lower())
        return list(set(tables))  # Deduplicate
