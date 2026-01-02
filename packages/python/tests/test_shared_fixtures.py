"""Tests that run shared JSON fixtures for cross-language parity."""

import json
from pathlib import Path
from typing import Any

import pytest

import proxql
from proxql import RuleSeverity, SecurityConfig

FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "shared" / "test-cases"


def load_test_cases() -> list[tuple[str, dict[str, Any]]]:
    """Load all shared test fixtures."""
    cases: list[tuple[str, dict[str, Any]]] = []

    if not FIXTURES_DIR.exists():
        return cases

    for file in FIXTURES_DIR.rglob("*.json"):
        try:
            data = json.loads(file.read_text())
            fixture_name = data.get("name", file.stem)
            for test in data.get("tests", []):
                test_name = test.get("description", test["sql"][:50])
                cases.append((f"{fixture_name}: {test_name}", test))
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Warning: Failed to parse {file}: {e}")

    return cases


def convert_security_config(security: bool | dict[str, Any] | None) -> bool | SecurityConfig:
    """Convert JSON security config to Python SecurityConfig."""
    if security is None:
        return True
    if isinstance(security, bool):
        return security

    # Map camelCase to snake_case
    severity_map = {
        "LOW": RuleSeverity.LOW,
        "MEDIUM": RuleSeverity.MEDIUM,
        "HIGH": RuleSeverity.HIGH,
        "CRITICAL": RuleSeverity.CRITICAL,
    }

    kwargs: dict[str, Any] = {}

    if "minimumSeverity" in security:
        kwargs["minimum_severity"] = severity_map.get(
            security["minimumSeverity"], RuleSeverity.HIGH
        )

    if "failOnLow" in security:
        kwargs["fail_on_low"] = security["failOnLow"]

    if "disabledRules" in security:
        kwargs["disabled_rules"] = set(security["disabledRules"])

    if "enabledRules" in security:
        kwargs["enabled_rules"] = set(security["enabledRules"])

    return SecurityConfig(**kwargs)


test_cases = load_test_cases()


@pytest.mark.skipif(len(test_cases) == 0, reason="No shared fixtures found")
@pytest.mark.parametrize("name,test_case", test_cases)
def test_shared_fixture(name: str, test_case: dict[str, Any]) -> None:
    """Run a shared test case."""
    sql = test_case["sql"]
    options = test_case.get("options", {})
    expected = test_case["expected"]

    # Build validation kwargs
    kwargs: dict[str, Any] = {}

    if "mode" in options:
        kwargs["mode"] = options["mode"]

    if "allowedTables" in options:
        kwargs["allowed_tables"] = options["allowedTables"]

    if "dialect" in options:
        kwargs["dialect"] = options["dialect"]

    if "security" in options:
        kwargs["security"] = convert_security_config(options["security"])

    # Run validation
    result = proxql.validate(sql, **kwargs)

    # Check is_safe
    assert result.is_safe == expected["isSafe"], (
        f"Expected is_safe={expected['isSafe']}, got {result.is_safe}. "
        f"Reason: {result.reason}"
    )

    # Check reason contains substring (if specified and query is unsafe)
    if "reasonContains" in expected and not expected["isSafe"]:
        assert expected["reasonContains"].lower() in (result.reason or "").lower(), (
            f"Expected reason to contain '{expected['reasonContains']}', "
            f"got '{result.reason}'"
        )

    # Check statement type (if specified)
    if "statementType" in expected:
        assert result.statement_type == expected["statementType"], (
            f"Expected statement_type={expected['statementType']}, "
            f"got {result.statement_type}"
        )

    # Check tables contain (if specified)
    if "tablesContain" in expected:
        result_tables_lower = [t.lower() for t in result.tables]
        for table in expected["tablesContain"]:
            assert table.lower() in result_tables_lower, (
                f"Expected tables to contain '{table}', got {result.tables}"
            )

