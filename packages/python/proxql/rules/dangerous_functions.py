"""Rule for detecting dangerous SQL functions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlglot import exp

from .base import Rule, RuleResult, RuleSeverity
from .registry import RuleRegistry

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class SystemCommandRule(Rule):
    """Detects functions that can execute system commands.

    These functions allow arbitrary OS command execution from SQL:
    - SQL Server: xp_cmdshell, xp_regread, xp_regwrite
    - PostgreSQL: COPY FROM PROGRAM (handled by file_access rule)

    CRITICAL severity - this is Remote Code Execution.
    """

    @property
    def rule_id(self) -> str:
        return "system-command"

    @property
    def name(self) -> str:
        return "System Command Execution Detection"

    @property
    def description(self) -> str:
        return (
            "Detects SQL functions that can execute operating system commands, "
            "such as xp_cmdshell on SQL Server."
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
        """Check for system command functions."""

        # SQL Server extended stored procedures
        dangerous_procs = {
            # Command execution
            "xp_cmdshell",
            # Registry access
            "xp_regread",
            "xp_regwrite",
            "xp_regdeletekey",
            "xp_regdeletevalue",
            "xp_regenumkeys",
            "xp_regenumvalues",
            # Other dangerous xp_ procs
            "xp_servicecontrol",
            "xp_availablemedia",
            "xp_dirtree",
            "xp_subdirs",
            "xp_terminate_process",
            # OLE automation
            "sp_oacreate",
            "sp_oamethod",
            "sp_oadestroy",
        }

        # Check Anonymous (user-defined) functions
        for func in expr.find_all(exp.Anonymous):
            func_name = func.name.lower() if func.name else ""
            if func_name in dangerous_procs:
                return self._fail(
                    f"System command function '{func_name}' detected - RCE attempted",
                    {"pattern": "system_function", "function": func_name},
                )

        # Check all function types
        for fn in expr.find_all(exp.Func):
            fn_name = ""
            if hasattr(fn, "name") and fn.name:
                fn_name = fn.name.lower()
            elif hasattr(fn, "this") and fn.this:
                fn_name = str(fn.this).lower()

            if fn_name in dangerous_procs:
                return self._fail(
                    f"System command function '{fn_name}' detected - RCE attempted",
                    {"pattern": "system_function", "function": fn_name},
                )

        return self._pass()


class DangerousFunctionsRule(Rule):
    """Detects various dangerous SQL functions.

    This rule catches functions that could be used for:
    - Information disclosure (VERSION(), USER(), DATABASE())
    - Sleep/delay attacks (SLEEP(), WAITFOR, BENCHMARK())
    - Other risky operations

    MEDIUM severity - these aren't always dangerous but indicate
    potential reconnaissance or attack attempts.
    """

    @property
    def rule_id(self) -> str:
        return "dangerous-functions"

    @property
    def name(self) -> str:
        return "Dangerous Functions Detection"

    @property
    def description(self) -> str:
        return (
            "Detects SQL functions commonly used in attacks, such as "
            "SLEEP for timing attacks or VERSION for reconnaissance."
        )

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for dangerous functions."""

        # Time-delay functions (used in blind SQL injection)
        timing_functions = {
            "sleep",  # MySQL, PostgreSQL
            "pg_sleep",  # PostgreSQL
            "pg_sleep_for",  # PostgreSQL
            "pg_sleep_until",  # PostgreSQL
            "waitfor",  # SQL Server (usually WAITFOR DELAY)
            "benchmark",  # MySQL (can cause DoS)
        }

        # Info disclosure functions (reconnaissance)
        info_functions = {
            "version",
            "@@version",
            "database",
            "current_database",
            "current_user",
            "session_user",
            "system_user",
            "user",
            "current_schema",
        }

        # Check Anonymous functions
        for func in expr.find_all(exp.Anonymous):
            func_name = func.name.lower() if func.name else ""

            if func_name in timing_functions:
                return self._fail(
                    f"Timing attack function '{func_name}' detected",
                    {"pattern": "timing_function", "function": func_name},
                )

            if func_name in info_functions:
                return self._fail(
                    f"Information disclosure function '{func_name}' detected",
                    {"pattern": "info_function", "function": func_name},
                )

        # Check regular function calls
        for fn in expr.find_all(exp.Func):
            fn_name = ""
            if hasattr(fn, "name") and fn.name:
                fn_name = fn.name.lower()
            else:
                # Get class name for built-in functions
                fn_name = type(fn).__name__.lower()

            if fn_name in timing_functions:
                return self._fail(
                    f"Timing attack function '{fn_name}' detected",
                    {"pattern": "timing_function", "function": fn_name},
                )

        return self._pass()


# Register all rules
_registry = RuleRegistry.get_instance()
_registry.register(SystemCommandRule())
_registry.register(DangerousFunctionsRule())
