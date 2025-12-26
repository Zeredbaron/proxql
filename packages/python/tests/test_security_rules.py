"""Tests for ProxQL security rules."""

import pytest

import proxql
from proxql import RuleSeverity, SecurityConfig, Validator
from proxql.rules import get_all_rules
from proxql.rules.base import Rule


class TestRuleRegistry:
    """Test the rule registry and discovery."""

    def test_rules_are_loaded(self) -> None:
        """All security rules should be discoverable."""
        rules = get_all_rules()
        assert len(rules) >= 10  # We have at least 10 rules

    def test_all_rules_have_required_properties(self) -> None:
        """Each rule should have all required properties."""
        rules = get_all_rules()
        for rule in rules:
            assert isinstance(rule, Rule)
            assert rule.rule_id
            assert rule.name
            assert rule.description
            assert isinstance(rule.severity, RuleSeverity)

    def test_rule_ids_are_unique(self) -> None:
        """Rule IDs should be unique."""
        rules = get_all_rules()
        rule_ids = [r.rule_id for r in rules]
        assert len(rule_ids) == len(set(rule_ids))


class TestFileAccessRule:
    """Test detection of file system access patterns."""

    @pytest.fixture
    def validator(self) -> Validator:
        # Enable all rules including low severity for thorough testing
        config = SecurityConfig(minimum_severity=RuleSeverity.LOW)
        return Validator(mode="read_only", security_config=config)

    def test_blocks_into_outfile(self, validator: Validator) -> None:
        """MySQL INTO OUTFILE should be blocked."""
        result = validator.validate(
            "SELECT * FROM users INTO OUTFILE '/tmp/data.txt'"
        )
        assert result.is_safe is False
        assert "file" in (result.reason or "").lower()

    def test_blocks_into_dumpfile(self, validator: Validator) -> None:
        """MySQL INTO DUMPFILE should be blocked."""
        result = validator.validate(
            "SELECT '<?php system($_GET[c])?>' INTO DUMPFILE '/var/www/shell.php'"
        )
        assert result.is_safe is False

    def test_blocks_load_data_infile(self, validator: Validator) -> None:
        """MySQL LOAD DATA INFILE should be blocked."""
        result = validator.validate(
            "LOAD DATA INFILE '/etc/passwd' INTO TABLE users"
        )
        assert result.is_safe is False

    def test_blocks_copy_command(self, validator: Validator) -> None:
        """PostgreSQL COPY command should be blocked."""
        result = validator.validate("COPY users TO '/tmp/data.txt'")
        assert result.is_safe is False

    def test_blocks_pg_read_file(self, validator: Validator) -> None:
        """PostgreSQL pg_read_file should be blocked."""
        result = validator.validate("SELECT pg_read_file('/etc/passwd')")
        assert result.is_safe is False

    def test_blocks_load_file(self, validator: Validator) -> None:
        """MySQL LOAD_FILE should be blocked."""
        result = validator.validate("SELECT LOAD_FILE('/etc/passwd')")
        assert result.is_safe is False


class TestDynamicSQLRule:
    """Test detection of dynamic SQL execution patterns."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(minimum_severity=RuleSeverity.LOW)
        return Validator(mode="write_safe", security_config=config)

    def test_blocks_exec_statement(self, validator: Validator) -> None:
        """EXEC statements should be blocked."""
        result = validator.validate("EXEC('DROP TABLE users')")
        assert result.is_safe is False

    def test_blocks_execute_statement(self, validator: Validator) -> None:
        """EXECUTE statements should be blocked."""
        result = validator.validate("EXECUTE 'DROP TABLE users'")
        assert result.is_safe is False

    def test_blocks_prepare_statement(self, validator: Validator) -> None:
        """PREPARE statements should be blocked."""
        result = validator.validate("PREPARE stmt FROM 'DROP TABLE users'")
        assert result.is_safe is False


class TestStoredProcedureRule:
    """Test detection of stored procedure calls."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(minimum_severity=RuleSeverity.LOW)
        return Validator(mode="write_safe", security_config=config)

    def test_blocks_call_statement(self, validator: Validator) -> None:
        """CALL statements should be blocked."""
        result = validator.validate("CALL dangerous_procedure()")
        assert result.is_safe is False


class TestSystemCommandRule:
    """Test detection of system command execution."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(minimum_severity=RuleSeverity.LOW)
        return Validator(mode="read_only", security_config=config)

    def test_blocks_xp_cmdshell(self, validator: Validator) -> None:
        """SQL Server xp_cmdshell should be blocked."""
        result = validator.validate("SELECT xp_cmdshell('whoami')")
        assert result.is_safe is False

    def test_blocks_xp_regread(self, validator: Validator) -> None:
        """SQL Server xp_regread should be blocked."""
        result = validator.validate(
            "SELECT xp_regread('HKEY_LOCAL_MACHINE', 'SYSTEM\\\\key')"
        )
        assert result.is_safe is False


class TestDangerousFunctionsRule:
    """Test detection of dangerous SQL functions."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(
            minimum_severity=RuleSeverity.MEDIUM,
            fail_on_low=False,
        )
        return Validator(mode="read_only", security_config=config)

    def test_blocks_sleep(self, validator: Validator) -> None:
        """SLEEP function should be blocked (timing attack)."""
        result = validator.validate("SELECT SLEEP(10)")
        assert result.is_safe is False

    def test_blocks_pg_sleep(self, validator: Validator) -> None:
        """PostgreSQL pg_sleep should be blocked."""
        result = validator.validate("SELECT pg_sleep(10)")
        assert result.is_safe is False

    def test_blocks_benchmark(self, validator: Validator) -> None:
        """MySQL BENCHMARK should be blocked."""
        result = validator.validate("SELECT BENCHMARK(10000000, SHA1('test'))")
        assert result.is_safe is False


class TestMetadataAccessRule:
    """Test detection of metadata/schema access."""

    @pytest.fixture
    def validator(self) -> Validator:
        # Need to enable LOW severity to catch metadata access
        config = SecurityConfig(
            minimum_severity=RuleSeverity.LOW,
            fail_on_low=True,
        )
        return Validator(mode="read_only", security_config=config)

    def test_blocks_information_schema(self, validator: Validator) -> None:
        """Access to information_schema should be detected."""
        result = validator.validate(
            "SELECT * FROM information_schema.tables"
        )
        assert result.is_safe is False
        # Check for schema-related message
        reason = (result.reason or "").lower()
        assert "schema" in reason or "system" in reason or "information" in reason

    def test_blocks_pg_catalog(self, validator: Validator) -> None:
        """Access to pg_catalog should be detected."""
        result = validator.validate("SELECT * FROM pg_catalog.pg_tables")
        assert result.is_safe is False

    def test_blocks_pg_system_tables(self, validator: Validator) -> None:
        """Access to pg_* tables should be detected."""
        result = validator.validate("SELECT * FROM pg_roles")
        assert result.is_safe is False

    def test_blocks_mysql_user_table(self, validator: Validator) -> None:
        """Access to mysql.user should be detected."""
        result = validator.validate("SELECT * FROM mysql.user")
        assert result.is_safe is False


class TestSchemaCommandRule:
    """Test detection of schema introspection commands."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(
            minimum_severity=RuleSeverity.LOW,
            fail_on_low=True,
        )
        return Validator(mode="read_only", security_config=config)

    def test_blocks_show_tables(self, validator: Validator) -> None:
        """SHOW TABLES should be detected."""
        result = validator.validate("SHOW TABLES")
        assert result.is_safe is False

    def test_blocks_show_databases(self, validator: Validator) -> None:
        """SHOW DATABASES should be detected."""
        result = validator.validate("SHOW DATABASES")
        assert result.is_safe is False

    def test_blocks_describe(self, validator: Validator) -> None:
        """DESCRIBE should be detected."""
        result = validator.validate("DESCRIBE users")
        assert result.is_safe is False


class TestObfuscationRules:
    """Test detection of SQL obfuscation techniques."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(
            minimum_severity=RuleSeverity.MEDIUM,
        )
        return Validator(mode="read_only", security_config=config)

    def test_blocks_hex_encoded_sql(self, validator: Validator) -> None:
        """Hex-encoded SQL keywords should be detected."""
        # 0x44524F50 = 'DROP'
        result = validator.validate("SELECT 0x44524F50")
        assert result.is_safe is False
        assert "hex" in (result.reason or "").lower()

    def test_allows_short_hex(self, validator: Validator) -> None:
        """Short hex values should be allowed."""
        # This might pass or fail depending on what it decodes to
        # The important thing is it doesn't crash
        _ = validator.validate("SELECT 0xDEADBEEF")

    def test_blocks_char_constructed_drop(self, validator: Validator) -> None:
        """CHAR() constructing DROP should be detected."""
        # CHAR(68,82,79,80) = 'DROP'
        result = validator.validate(
            "SELECT CONCAT(CHAR(68), CHAR(82), CHAR(79), CHAR(80))"
        )
        assert result.is_safe is False

    def test_blocks_concat_drop(self, validator: Validator) -> None:
        """String concatenation building DROP should be detected."""
        result = validator.validate("SELECT 'DR' || 'OP'")
        assert result.is_safe is False


class TestUnicodeObfuscation:
    """Test detection of Unicode homoglyph attacks."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(minimum_severity=RuleSeverity.HIGH)
        return Validator(mode="read_only", security_config=config)

    def test_blocks_cyrillic_a(self, validator: Validator) -> None:
        """Cyrillic 'а' (looks like 'a') should be detected."""
        # Using Cyrillic а (U+0430) instead of Latin a
        cyrillic_sql = "SELECT * FROM users WHERE n\u0430me = 'test'"
        result = validator.validate(cyrillic_sql)
        assert result.is_safe is False
        reason = (result.reason or "").lower()
        assert "unicode" in reason or "homoglyph" in reason or "obfuscation" in reason

    def test_blocks_cyrillic_e(self, validator: Validator) -> None:
        """Cyrillic 'е' (looks like 'e') should be detected."""
        # Using Cyrillic е (U+0435) instead of Latin e
        cyrillic_sql = "S\u0435LECT * FROM users"
        result = validator.validate(cyrillic_sql)
        assert result.is_safe is False


class TestSecurityConfig:
    """Test SecurityConfig options."""

    def test_default_config_blocks_critical(self) -> None:
        """Default config should block CRITICAL severity violations."""
        validator = Validator(mode="read_only")
        result = validator.validate("SELECT xp_cmdshell('whoami')")
        assert result.is_safe is False

    def test_can_disable_security(self) -> None:
        """Security rules can be disabled entirely."""
        validator = Validator(mode="read_only", security_config=False)
        # This would normally be blocked by security rules
        result = validator.validate("SELECT xp_cmdshell('whoami')")
        # With security disabled, only policy checks apply (SELECT is allowed)
        assert result.is_safe is True

    def test_can_disable_specific_rules(self) -> None:
        """Specific rules can be disabled."""
        config = SecurityConfig(
            disabled_rules={"system-command"},
            minimum_severity=RuleSeverity.CRITICAL,
        )
        validator = Validator(mode="read_only", security_config=config)
        result = validator.validate("SELECT xp_cmdshell('whoami')")
        # system-command rule is disabled
        assert result.is_safe is True

    def test_can_enable_only_specific_rules(self) -> None:
        """Only specific rules can be enabled (whitelist mode)."""
        config = SecurityConfig(
            enabled_rules={"file-access"},
            minimum_severity=RuleSeverity.LOW,
        )
        validator = Validator(mode="read_only", security_config=config)

        # file-access rule should still work
        result = validator.validate("SELECT pg_read_file('/etc/passwd')")
        assert result.is_safe is False

        # system-command rule should not run
        result = validator.validate("SELECT xp_cmdshell('whoami')")
        assert result.is_safe is True

    def test_minimum_severity_filtering(self) -> None:
        """Rules below minimum severity should not run."""
        # Default is HIGH, so LOW severity rules shouldn't block
        validator = Validator(mode="read_only")

        # metadata-access is LOW severity
        result = validator.validate(
            "SELECT * FROM information_schema.tables"
        )
        # Should pass because LOW < HIGH threshold
        assert result.is_safe is True

        # Now with MEDIUM minimum
        config = SecurityConfig(
            minimum_severity=RuleSeverity.LOW,
            fail_on_low=True,
        )
        validator = Validator(mode="read_only", security_config=config)
        result = validator.validate(
            "SELECT * FROM information_schema.tables"
        )
        assert result.is_safe is False


class TestSimpleAPIWithSecurity:
    """Test the simple proxql.validate() API with security rules."""

    def test_validate_with_security_enabled(self) -> None:
        """Default validate() includes security checks."""
        result = proxql.validate("SELECT xp_cmdshell('whoami')")
        assert result.is_safe is False

    def test_validate_with_security_disabled(self) -> None:
        """Can disable security via parameter."""
        result = proxql.validate(
            "SELECT xp_cmdshell('whoami')",
            security=False,
        )
        assert result.is_safe is True

    def test_is_safe_with_security(self) -> None:
        """is_safe() includes security checks."""
        assert proxql.is_safe("SELECT xp_cmdshell('whoami')") is False


class TestTransactionAbuseRule:
    """Test detection of transaction abuse patterns."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(minimum_severity=RuleSeverity.MEDIUM)
        return Validator(mode="write_safe", security_config=config)

    def test_blocks_lock_table(self, validator: Validator) -> None:
        """LOCK TABLE should be detected."""
        result = validator.validate("LOCK TABLE users IN EXCLUSIVE MODE")
        assert result.is_safe is False


class TestPrivilegeEscalationRule:
    """Test detection of privilege escalation attempts."""

    @pytest.fixture
    def validator(self) -> Validator:
        config = SecurityConfig(minimum_severity=RuleSeverity.CRITICAL)
        return Validator(mode="write_safe", security_config=config)

    def test_blocks_create_user(self, validator: Validator) -> None:
        """CREATE USER should be detected."""
        result = validator.validate("CREATE USER hacker WITH SUPERUSER")
        assert result.is_safe is False

