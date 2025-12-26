"""Rule for detecting dangerous statement types beyond basic DDL."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlglot import exp

from .base import Rule, RuleResult, RuleSeverity
from .registry import RuleRegistry

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class DynamicSQLRule(Rule):
    """Detects dynamic SQL execution patterns.

    Dynamic SQL can be used to bypass static analysis by constructing
    malicious queries at runtime. This rule catches:
    - EXEC/EXECUTE statements
    - PREPARE/EXECUTE IMMEDIATE
    - sp_executesql (SQL Server)

    CRITICAL severity because these can execute arbitrary SQL.
    """

    @property
    def rule_id(self) -> str:
        return "dynamic-sql"

    @property
    def name(self) -> str:
        return "Dynamic SQL Execution Detection"

    @property
    def description(self) -> str:
        return (
            "Detects dynamic SQL execution patterns like EXEC, EXECUTE, "
            "PREPARE/EXECUTE which can be used to bypass static analysis."
        )

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for dynamic SQL patterns."""
        stmt_type = expr.key.upper()

        # Check statement type directly
        dynamic_statements = {"EXECUTE", "EXEC", "PREPARE"}
        if stmt_type in dynamic_statements:
            return self._fail(
                f"{stmt_type} statement detected - dynamic SQL execution",
                {"pattern": "dynamic_statement", "statement_type": stmt_type},
            )

        # Check for EXECUTE as a command/function
        for cmd in expr.find_all(exp.Command):
            cmd_name = str(cmd.this).upper() if cmd.this else ""
            if cmd_name in {"EXEC", "EXECUTE", "EXECUTE IMMEDIATE"}:
                return self._fail(
                    f"Dynamic SQL command '{cmd_name}' detected",
                    {"pattern": "dynamic_command", "command": cmd_name},
                )

        # Check for sp_executesql and similar
        dangerous_procs = {
            "sp_executesql",
            "sp_sqlexec",
            "execute_immediate",
        }
        for func in expr.find_all(exp.Anonymous):
            func_name = func.name.lower() if func.name else ""
            if func_name in dangerous_procs:
                return self._fail(
                    f"Dynamic SQL procedure '{func_name}' detected",
                    {"pattern": "dynamic_procedure", "procedure": func_name},
                )

        return self._pass()


class StoredProcedureRule(Rule):
    """Detects stored procedure/function calls.

    Stored procedures can contain arbitrary logic and may bypass
    validation. This rule catches CALL statements.

    HIGH severity - procedures themselves may be safe, but calling
    unknown procedures is risky.
    """

    @property
    def rule_id(self) -> str:
        return "stored-procedure"

    @property
    def name(self) -> str:
        return "Stored Procedure Call Detection"

    @property
    def description(self) -> str:
        return "Detects CALL statements to stored procedures."

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for stored procedure calls."""
        stmt_type = expr.key.upper()

        if stmt_type == "CALL":
            return self._fail(
                "CALL statement detected - stored procedure execution",
                {"pattern": "call_statement"},
            )

        # Also check for CALL as a command
        for cmd in expr.find_all(exp.Command):
            cmd_name = str(cmd.this).upper() if cmd.this else ""
            if cmd_name == "CALL":
                return self._fail(
                    "CALL command detected - stored procedure execution",
                    {"pattern": "call_command"},
                )

        return self._pass()


class PrivilegeEscalationRule(Rule):
    """Detects user/role/permission manipulation.

    These statements can be used for privilege escalation attacks.
    Catches: CREATE USER, ALTER USER, CREATE ROLE, SET ROLE, etc.

    CRITICAL severity - can lead to full database takeover.
    """

    @property
    def rule_id(self) -> str:
        return "privilege-escalation"

    @property
    def name(self) -> str:
        return "Privilege Escalation Detection"

    @property
    def description(self) -> str:
        return (
            "Detects attempts to create users, modify roles, or change "
            "permissions that could lead to privilege escalation."
        )

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for privilege escalation patterns."""
        stmt_type = expr.key.upper()

        # Direct statement types for user/role manipulation
        privilege_statements = {
            "CREATEUSER",
            "ALTERUSER",
            "DROPUSER",
            "CREATEROLE",
            "ALTERROLE",
            "DROPROLE",
            "SETROLE",
        }

        if stmt_type in privilege_statements:
            return self._fail(
                f"{stmt_type} detected - privilege manipulation attempted",
                {"pattern": "privilege_statement", "statement_type": stmt_type},
            )

        # Check for CREATE/ALTER followed by USER/ROLE in command form
        for cmd in expr.find_all(exp.Command):
            cmd_text = str(cmd.this).upper() if cmd.this else ""
            # Check the expression text for user/role keywords
            expr_text = str(cmd.expression).upper() if cmd.expression else ""

            is_priv_cmd = cmd_text in {"CREATE", "ALTER", "DROP"}
            has_user_role = any(kw in expr_text for kw in ["USER", "ROLE", "LOGIN"])
            if is_priv_cmd and has_user_role:
                return self._fail(
                    f"{cmd_text} USER/ROLE detected - privilege manipulation",
                    {"pattern": "privilege_command", "command": cmd_text},
                )

        # Check for SET ROLE / SET SESSION AUTHORIZATION
        for set_expr in expr.find_all(exp.Set):
            set_sql = set_expr.sql().upper()
            if "ROLE" in set_sql or "SESSION AUTHORIZATION" in set_sql:
                return self._fail(
                    "SET ROLE/SESSION AUTHORIZATION detected",
                    {"pattern": "set_role", "sql_fragment": set_expr.sql()},
                )

        return self._pass()


class TransactionAbuseRule(Rule):
    """Detects potentially dangerous transaction patterns.

    Long-running or nested transactions can be used for DoS attacks.
    Also catches LOCK TABLE statements.

    MEDIUM severity - transactions are normal, but some patterns are risky.
    """

    @property
    def rule_id(self) -> str:
        return "transaction-abuse"

    @property
    def name(self) -> str:
        return "Transaction Abuse Detection"

    @property
    def description(self) -> str:
        return "Detects LOCK TABLE and other potentially abusive transaction patterns."

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for transaction abuse patterns."""
        stmt_type = expr.key.upper()

        # LOCK TABLE can be used for DoS
        if stmt_type in {"LOCK", "LOCKTABLE"}:
            return self._fail(
                "LOCK TABLE detected - potential DoS vector",
                {"pattern": "lock_table"},
            )

        # Check for LOCK in expression
        for _lock in expr.find_all(exp.Lock):
            return self._fail(
                "LOCK detected - potential DoS vector",
                {"pattern": "lock_expression"},
            )

        return self._pass()


# Register all rules
_registry = RuleRegistry.get_instance()
_registry.register(DynamicSQLRule())
_registry.register(StoredProcedureRule())
_registry.register(PrivilegeEscalationRule())
_registry.register(TransactionAbuseRule())
