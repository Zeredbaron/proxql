"""Rule for detecting file system access patterns in SQL."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlglot import exp

from .base import Rule, RuleResult, RuleSeverity
from .registry import RuleRegistry

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class FileAccessRule(Rule):
    """Detects SQL patterns that access the file system.

    This rule catches:
    - MySQL: INTO OUTFILE, INTO DUMPFILE, LOAD DATA INFILE
    - PostgreSQL: COPY TO/FROM, pg_read_file(), pg_write_file()
    - SQL Server: BULK INSERT, OPENROWSET with file paths

    These are CRITICAL severity because they can be used for:
    - Reading sensitive files (/etc/passwd, config files)
    - Writing web shells or malicious files
    - Exfiltrating data to attacker-controlled locations
    """

    @property
    def rule_id(self) -> str:
        return "file-access"

    @property
    def name(self) -> str:
        return "File System Access Detection"

    @property
    def description(self) -> str:
        return (
            "Detects SQL patterns that read from or write to the file system, "
            "including INTO OUTFILE, LOAD DATA INFILE, COPY commands, and "
            "file-related functions."
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
        """Check for file access patterns."""

        # Check for INTO OUTFILE / INTO DUMPFILE (MySQL)
        # These appear as Into expressions with specific properties
        for into in expr.find_all(exp.Into):
            # Check if it has file-related properties
            into_sql = into.sql().upper()
            if "OUTFILE" in into_sql or "DUMPFILE" in into_sql:
                return self._fail(
                    "INTO OUTFILE/DUMPFILE detected - file system write attempted",
                    {"pattern": "into_outfile", "sql_fragment": into.sql()},
                )

        # Check for LOAD DATA INFILE (MySQL)
        # sqlglot parses this as LoadData expression
        for load in expr.find_all(exp.LoadData):
            return self._fail(
                "LOAD DATA INFILE detected - file system read attempted",
                {"pattern": "load_data", "sql_fragment": load.sql()},
            )

        # Check for COPY command (PostgreSQL)
        # sqlglot parses COPY as Copy expression
        for copy in expr.find_all(exp.Copy):
            return self._fail(
                "COPY command detected - file system access attempted",
                {"pattern": "copy", "sql_fragment": copy.sql()},
            )

        # Check for dangerous file functions in any context
        dangerous_file_funcs = {
            # PostgreSQL
            "pg_read_file",
            "pg_read_binary_file",
            "pg_write_file",
            "pg_ls_dir",
            "pg_stat_file",
            "lo_import",
            "lo_export",
            # MySQL
            "load_file",
            # SQL Server
            "openrowset",
            "opendatasource",
            "bulk",
        }

        for func in expr.find_all(exp.Anonymous):
            func_name = func.name.lower() if func.name else ""
            if func_name in dangerous_file_funcs:
                return self._fail(
                    f"Dangerous file function '{func_name}' detected",
                    {"pattern": "dangerous_function", "function": func_name},
                )

        # Also check regular function calls
        for fn in expr.find_all(exp.Func):
            fn_name = fn.name.lower() if hasattr(fn, "name") and fn.name else ""
            # Get class name as fallback
            if not fn_name:
                fn_name = type(fn).__name__.lower()
            if fn_name in dangerous_file_funcs:
                return self._fail(
                    f"Dangerous file function '{fn_name}' detected",
                    {"pattern": "dangerous_function", "function": fn_name},
                )

        return self._pass()


# Register the rule
RuleRegistry.get_instance().register(FileAccessRule())
