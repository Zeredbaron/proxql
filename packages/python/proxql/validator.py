"""Main Validator class - the primary entry point for ProxQL."""

from __future__ import annotations

from .exceptions import ParseError
from .parser import Parser
from .policy import Mode, PolicyEngine
from .result import ValidationResult
from .security import SecurityChecker, SecurityConfig


class Validator:
    """SQL validator that checks queries against configurable policies.

    This is the main entry point for ProxQL. Create a Validator with your
    desired configuration, then call validate() on SQL strings.

    The validation process has two phases:
    1. Policy checks: Statement types and table allowlists (fast)
    2. Security rules: Deep AST analysis for injection patterns

    Example:
        >>> validator = Validator(mode="read_only")
        >>> result = validator.validate("SELECT * FROM users")
        >>> result.is_safe
        True

        >>> result = validator.validate("DROP TABLE users")
        >>> result.is_safe
        False

        # With security rules disabled
        >>> validator = Validator(mode="read_only", security_config=None)
    """

    def __init__(
        self,
        mode: Mode | str = Mode.READ_ONLY,
        allowed_tables: set[str] | list[str] | None = None,
        allowed_statements: set[str] | list[str] | None = None,
        blocked_statements: set[str] | list[str] | None = None,
        dialect: str | None = None,
        security_config: SecurityConfig | None | bool = True,
    ) -> None:
        """Initialize the validator.

        Args:
            mode: Validation mode. Options:
                - "read_only": Only SELECT allowed (default)
                - "write_safe": SELECT, INSERT, UPDATE allowed
                - "custom": Use allowed_statements/blocked_statements
            allowed_tables: Optional whitelist of accessible table names.
            allowed_statements: For custom mode, statements to allow.
            blocked_statements: For custom mode, statements to block.
            dialect: SQL dialect ('postgres', 'mysql', 'snowflake', etc).
            security_config: Security rule configuration. Options:
                - True (default): Default config (HIGH+ severity)
                - SecurityConfig: Custom configuration
                - None/False: Disable security rules
        """
        self._parser = Parser(dialect=dialect)
        self._dialect = dialect
        self._policy = PolicyEngine(
            mode=mode,
            allowed_tables=allowed_tables,
            allowed_statements=allowed_statements,
            blocked_statements=blocked_statements,
        )

        # Set up security checker
        self._security: SecurityChecker | None
        if security_config is True:
            self._security = SecurityChecker(SecurityConfig())
        elif security_config is False or security_config is None:
            self._security = None
        else:
            self._security = SecurityChecker(security_config)

    def validate(self, sql: str) -> ValidationResult:
        """Validate a SQL query string.

        Parses the SQL and checks it against:
        1. Configured policies (statement types, table allowlists)
        2. Security rules (injection patterns, dangerous functions, etc.)

        Multi-statement queries are all validated; if any statement fails,
        the entire query is considered unsafe.

        Args:
            sql: The SQL query string to validate.

        Returns:
            ValidationResult with is_safe=True if the query passes all checks,
            or is_safe=False with a reason if blocked.

        Note:
            Parse errors are treated as unsafe (is_safe=False) with the
            parse error message as the reason.
        """
        # Handle empty/whitespace input
        sql = sql.strip()
        if not sql:
            return ValidationResult(
                is_safe=False,
                reason="Empty query",
            )

        # Try to parse
        try:
            statements = self._parser.parse(sql)
        except ParseError as e:
            return ValidationResult(
                is_safe=False,
                reason=f"Parse error: {e}",
            )

        if not statements:
            return ValidationResult(
                is_safe=False,
                reason="No valid SQL statements found",
            )

        # Validate each statement
        all_tables: list[str] = []
        for stmt in statements:
            statement_type = self._parser.get_statement_type(stmt)
            tables = self._parser.extract_tables(stmt)
            all_tables.extend(tables)

            # Phase 1: Policy checks (statement type, table allowlist)
            result = self._policy.evaluate(stmt, statement_type, tables)
            if not result.is_safe:
                return result

            # Phase 2: Security rule checks
            if self._security is not None:
                sec_result = self._security.check(stmt, dialect=self._dialect, raw_sql=sql)
                if not sec_result.passed:
                    violation = sec_result.first_violation
                    if violation is not None and violation.message:
                        msg = violation.message
                    else:
                        msg = "Security check failed"
                    return ValidationResult(
                        is_safe=False,
                        reason=msg,
                        statement_type=statement_type,
                        tables=tables,
                    )

        # All statements passed
        # Return result with combined info from all statements
        final_type = (
            self._parser.get_statement_type(statements[0]) if len(statements) == 1 else "MULTI"
        )
        return ValidationResult(
            is_safe=True,
            statement_type=final_type,
            tables=list(set(all_tables)),
        )
