"""Security checker that orchestrates security rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .rules import RuleSeverity, get_all_rules

if TYPE_CHECKING:
    from sqlglot.expressions import Expression

    from .rules import Rule, RuleResult


@dataclass
class SecurityConfig:
    """Configuration for security rule checking.

    Attributes:
        enabled: Whether security checking is enabled at all.
        minimum_severity: Only run rules with this severity or higher.
        disabled_rules: Set of rule IDs to skip.
        enabled_rules: If set, ONLY run these rules (whitelist mode).
        fail_on_low: Whether LOW severity violations should fail validation.
    """

    enabled: bool = True
    minimum_severity: RuleSeverity = RuleSeverity.HIGH
    disabled_rules: set[str] = field(default_factory=set)
    enabled_rules: set[str] | None = None
    fail_on_low: bool = False

    def should_run_rule(self, rule: Rule) -> bool:
        """Determine if a specific rule should be run."""
        if not self.enabled:
            return False

        # Check whitelist mode
        if self.enabled_rules is not None:
            return rule.rule_id in self.enabled_rules

        # Check blacklist
        if rule.rule_id in self.disabled_rules:
            return False

        # Check severity threshold
        severity_order = {
            RuleSeverity.CRITICAL: 4,
            RuleSeverity.HIGH: 3,
            RuleSeverity.MEDIUM: 2,
            RuleSeverity.LOW: 1,
        }
        return severity_order[rule.severity] >= severity_order[self.minimum_severity]

    def should_fail_on(self, result: RuleResult) -> bool:
        """Determine if a rule result should cause validation to fail."""
        if result.passed:
            return False
        # LOW severity might be informational only
        is_low_info_only = result.severity == RuleSeverity.LOW and not self.fail_on_low
        return not is_low_info_only


@dataclass(frozen=True)
class SecurityCheckResult:
    """Result of running security checks.

    Attributes:
        passed: True if no blocking violations were found.
        violations: List of rule results that failed.
        warnings: List of LOW severity results (informational).
    """

    passed: bool
    violations: list[RuleResult] = field(default_factory=list)
    warnings: list[RuleResult] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.passed

    @property
    def first_violation(self) -> RuleResult | None:
        """Get the first violation, if any."""
        return self.violations[0] if self.violations else None

    @property
    def message(self) -> str | None:
        """Get a human-readable message for the first violation."""
        if self.violations:
            v = self.violations[0]
            return f"[{v.severity.value.upper()}] {v.message}"
        return None


class SecurityChecker:
    """Orchestrates security rules against parsed SQL.

    This class manages the execution of security rules and aggregates
    their results. It's used internally by the Validator.

    Example:
        checker = SecurityChecker(config=SecurityConfig(
            minimum_severity=RuleSeverity.HIGH,
            disabled_rules={"metadata-access"},
        ))

        result = checker.check(parsed_sql)
        if not result.passed:
            print(f"Blocked: {result.message}")
    """

    def __init__(self, config: SecurityConfig | None = None) -> None:
        """Initialize the security checker.

        Args:
            config: Security configuration. If None, uses defaults.
        """
        self.config = config or SecurityConfig()
        self._rules: list[Rule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all registered rules."""
        self._rules = get_all_rules()

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> SecurityCheckResult:
        """Run all applicable security rules against the expression.

        Args:
            expr: The parsed SQL expression to check.
            dialect: SQL dialect for dialect-specific checks.
            **context: Additional context passed to rules.

        Returns:
            SecurityCheckResult with pass/fail and all violations.
        """
        violations: list[RuleResult] = []
        warnings: list[RuleResult] = []

        for rule in self._rules:
            if not self.config.should_run_rule(rule):
                continue

            result = rule.check(expr, dialect=dialect, **context)

            if not result.passed:
                if result.severity == RuleSeverity.LOW and not self.config.fail_on_low:
                    warnings.append(result)
                elif self.config.should_fail_on(result):
                    violations.append(result)

        return SecurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    @property
    def rules(self) -> list[Rule]:
        """Get all loaded rules."""
        return self._rules.copy()

    def get_active_rules(self) -> list[Rule]:
        """Get only the rules that would actually run."""
        return [r for r in self._rules if self.config.should_run_rule(r)]
