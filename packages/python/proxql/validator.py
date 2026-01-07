"""Main Validator class - the primary entry point for ProxQL."""

from __future__ import annotations

from .cost import CostEstimate, CostEstimator, CostLevel
from .exceptions import ParseError
from .limits import LimitEnforcer
from .parser import Parser
from .policy import Mode, PolicyEngine
from .result import ValidationResult
from .security import SecurityChecker, SecurityConfig


class Validator:
    """SQL validator that checks queries against configurable policies.

    This is the main entry point for ProxQL. Create a Validator with your
    desired configuration, then call validate() on SQL strings.

    The validation process has multiple phases:
    1. Policy checks: Statement types and table allowlists (fast)
    2. Security rules: Deep AST analysis for injection patterns
    3. Limit enforcement: Row limit checks (optional)
    4. Cost estimation: Query complexity analysis (optional)

    Example:
        >>> validator = Validator(mode="read_only")
        >>> result = validator.validate("SELECT * FROM users")
        >>> result.is_safe
        True

        >>> result = validator.validate("DROP TABLE users")
        >>> result.is_safe
        False

        # With row limits
        >>> validator = Validator(mode="read_only", max_rows=1000)
        >>> result = validator.validate("SELECT * FROM users LIMIT 5000")
        >>> result.is_safe
        False

        # With cost estimation
        >>> validator = Validator(mode="read_only", estimate_cost=True)
        >>> result = validator.validate("SELECT * FROM a JOIN b JOIN c JOIN d")
        >>> result.cost.level
        <CostLevel.HIGH: 3>
    """

    def __init__(
        self,
        mode: Mode | str = Mode.READ_ONLY,
        allowed_tables: set[str] | list[str] | None = None,
        allowed_statements: set[str] | list[str] | None = None,
        blocked_statements: set[str] | list[str] | None = None,
        dialect: str | None = None,
        security_config: SecurityConfig | None | bool = True,
        max_rows: int | None = None,
        require_limit: bool = False,
        estimate_cost: bool = False,
        block_high_cost: bool = False,
        max_cost_level: CostLevel | str | None = None,
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
            max_rows: Maximum allowed LIMIT value. Queries with LIMIT > max_rows
                      are rejected. None means no limit.
            require_limit: If True, SELECT queries without LIMIT are rejected.
            estimate_cost: If True, estimate query cost/complexity.
            block_high_cost: If True, block queries with HIGH or EXTREME cost.
            max_cost_level: Maximum allowed cost level. Queries exceeding this
                           are rejected. Can be CostLevel or string like "MEDIUM".
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

        # Set up limit enforcer
        self._limit_enforcer: LimitEnforcer | None = None
        if max_rows is not None or require_limit:
            self._limit_enforcer = LimitEnforcer(
                max_rows=max_rows,
                require_limit=require_limit,
            )

        # Set up cost estimator
        self._estimate_cost = estimate_cost or block_high_cost or max_cost_level is not None
        self._cost_estimator: CostEstimator | None = None
        if self._estimate_cost:
            self._cost_estimator = CostEstimator()

        # Cost blocking settings
        self._block_high_cost = block_high_cost
        self._max_cost_level: CostLevel | None = None
        if max_cost_level is not None:
            if isinstance(max_cost_level, str):
                self._max_cost_level = CostLevel[max_cost_level.upper()]
            else:
                self._max_cost_level = max_cost_level
        elif block_high_cost:
            self._max_cost_level = CostLevel.MEDIUM

    def validate(self, sql: str) -> ValidationResult:
        """Validate a SQL query string.

        Parses the SQL and checks it against:
        1. Configured policies (statement types, table allowlists)
        2. Security rules (injection patterns, dangerous functions, etc.)
        3. Row limit enforcement (if configured)
        4. Cost estimation (if configured)

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
        all_warnings: list[str] = []
        combined_cost: CostEstimate | None = None
        limit_value: int | None = None

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

            # Phase 3: Limit enforcement
            if self._limit_enforcer is not None:
                limit_result = self._limit_enforcer.check(stmt)
                if not limit_result.is_ok:
                    return ValidationResult(
                        is_safe=False,
                        reason=limit_result.reason,
                        statement_type=statement_type,
                        tables=tables,
                    )
                if limit_result.limit_value is not None:
                    limit_value = limit_result.limit_value

            # Phase 4: Cost estimation
            if self._cost_estimator is not None:
                cost = self._cost_estimator.estimate(stmt)

                # Track highest cost across statements
                if combined_cost is None or cost.level > combined_cost.level:
                    combined_cost = cost

                # Check if cost exceeds maximum
                if self._max_cost_level is not None and cost.level > self._max_cost_level:
                    return ValidationResult(
                        is_safe=False,
                        reason=f"Query cost ({cost.level.name}) exceeds maximum allowed ({self._max_cost_level.name})",
                        statement_type=statement_type,
                        tables=tables,
                        cost=cost,
                    )

                # Add warnings for high-cost queries that aren't blocked
                if cost.level >= CostLevel.HIGH and self._max_cost_level is None:
                    all_warnings.append(
                        f"High cost query ({cost.level.name}): {', '.join(cost.factors)}"
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
            cost=combined_cost,
            limit_value=limit_value,
            warnings=all_warnings,
        )
