"""Rule for detecting metadata/schema reconnaissance."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlglot import exp

from .base import Rule, RuleResult, RuleSeverity
from .registry import RuleRegistry

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class MetadataAccessRule(Rule):
    """Detects access to database metadata/system tables.

    Attackers often query metadata tables to:
    - Enumerate database structure (tables, columns)
    - Find sensitive tables
    - Discover credentials stored in system tables

    This rule catches access to:
    - information_schema (standard SQL)
    - pg_catalog, pg_* tables (PostgreSQL)
    - mysql.* system tables (MySQL)
    - sys.*, master.* (SQL Server)

    LOW severity - metadata access isn't always malicious, but it's
    a common reconnaissance technique.
    """

    @property
    def rule_id(self) -> str:
        return "metadata-access"

    @property
    def name(self) -> str:
        return "Metadata/Schema Access Detection"

    @property
    def description(self) -> str:
        return (
            "Detects queries against system tables and information_schema "
            "which may indicate reconnaissance activity."
        )

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for metadata access patterns."""

        # System schemas to detect
        system_schemas = {
            # Standard SQL
            "information_schema",
            # PostgreSQL
            "pg_catalog",
            # MySQL
            "mysql",
            "performance_schema",
            # SQL Server
            "sys",
            "master",
            "msdb",
            "tempdb",
            # Oracle
            "system",
            "dba_",
            "all_",
            "user_",
        }

        # System table prefixes (for tables without schema qualifier)
        system_table_prefixes = {
            "pg_",  # PostgreSQL system tables
            "sqlite_",  # SQLite system tables
        }

        # Specific sensitive tables
        sensitive_tables = {
            # PostgreSQL
            "pg_shadow",
            "pg_authid",
            "pg_roles",
            "pg_user",
            "pg_tables",
            "pg_views",
            "pg_proc",
            # MySQL
            "user",  # mysql.user
            # SQL Server
            "syslogins",
            "sysobjects",
            "syscolumns",
            "sysusers",
        }

        # Check all table references
        for table in expr.find_all(exp.Table):
            table_name = table.name.lower() if table.name else ""
            schema_name = ""

            # Get schema/database qualifier
            if table.db:
                schema_name = str(table.db).lower()
            if table.catalog:
                schema_name = str(table.catalog).lower()

            # Check schema
            if schema_name in system_schemas:
                return self._fail(
                    f"Access to system schema '{schema_name}' detected",
                    {
                        "pattern": "system_schema",
                        "schema": schema_name,
                        "table": table_name,
                    },
                )

            # Check table prefixes
            for prefix in system_table_prefixes:
                if table_name.startswith(prefix):
                    return self._fail(
                        f"Access to system table '{table_name}' detected",
                        {"pattern": "system_table", "table": table_name},
                    )

            # Check specific sensitive tables
            if table_name in sensitive_tables:
                return self._fail(
                    f"Access to sensitive system table '{table_name}' detected",
                    {"pattern": "sensitive_table", "table": table_name},
                )

        return self._pass()


class SchemaCommandRule(Rule):
    """Detects schema introspection commands.

    Commands like SHOW, DESCRIBE, EXPLAIN can reveal database structure.

    LOW severity - these are normal operations but can indicate recon.
    """

    @property
    def rule_id(self) -> str:
        return "schema-commands"

    @property
    def name(self) -> str:
        return "Schema Introspection Command Detection"

    @property
    def description(self) -> str:
        return "Detects commands like SHOW, DESCRIBE, EXPLAIN that reveal database structure."

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for schema introspection commands."""
        stmt_type = expr.key.upper()

        # Direct statement types
        introspection_statements = {
            "SHOW",
            "DESCRIBE",
            "DESC",
            "EXPLAIN",
            # sqlglot compound names
            "SHOWTABLES",
            "SHOWDATABASES",
            "SHOWCOLUMNS",
            "SHOWSCHEMAS",
        }

        if stmt_type in introspection_statements:
            return self._fail(
                f"{stmt_type} command detected - schema introspection",
                {"pattern": "introspection_command", "command": stmt_type},
            )

        # Check for SHOW as a command
        for cmd in expr.find_all(exp.Command):
            cmd_name = str(cmd.this).upper() if cmd.this else ""
            if cmd_name in {"SHOW", "DESCRIBE", "DESC", "EXPLAIN"}:
                return self._fail(
                    f"{cmd_name} command detected - schema introspection",
                    {"pattern": "introspection_command", "command": cmd_name},
                )

        return self._pass()


# Register all rules
_registry = RuleRegistry.get_instance()
_registry.register(MetadataAccessRule())
_registry.register(SchemaCommandRule())
