"""Base classes and protocols for security rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class RuleSeverity(str, Enum):
    """Severity levels for rule violations.

    CRITICAL: Immediate security threat (RCE, file access, data destruction)
    HIGH: Dangerous operations that should almost always be blocked
    MEDIUM: Potentially dangerous, may be allowed in some contexts
    LOW: Informational, might indicate reconnaissance
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class RuleResult:
    """Result of a rule evaluation.

    Attributes:
        passed: True if no violations were detected
        rule_id: Identifier of the rule that was evaluated
        message: Human-readable description of the violation (if any)
        severity: Severity level of the violation
        details: Additional structured details about the violation
    """

    passed: bool
    rule_id: str
    message: str | None = None
    severity: RuleSeverity = RuleSeverity.HIGH
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Allow using RuleResult in boolean context."""
        return self.passed


class Rule(ABC):
    """Abstract base class for security rules.

    Each rule implements a specific security check against parsed SQL.
    Rules are designed to be:
    - Composable: Multiple rules can be applied to the same query
    - Configurable: Rules can be enabled/disabled and customized
    - Testable: Each rule is a self-contained unit

    Subclasses must implement:
    - rule_id: Unique identifier for the rule
    - name: Human-readable name
    - description: Detailed description of what the rule checks
    - severity: Default severity level
    - check(): The actual validation logic
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this rule (e.g., 'file-access')."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this rule."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of what this rule checks for."""
        ...

    @property
    @abstractmethod
    def severity(self) -> RuleSeverity:
        """Default severity level for violations of this rule."""
        ...

    @abstractmethod
    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check if the expression violates this rule.

        Args:
            expr: The parsed SQL expression to check
            dialect: SQL dialect (postgres, mysql, etc.) for dialect-specific checks
            **context: Additional context (e.g., allowed_tables, mode)

        Returns:
            RuleResult indicating pass/fail and details
        """
        ...

    def _pass(self) -> RuleResult:
        """Convenience method to return a passing result."""
        return RuleResult(passed=True, rule_id=self.rule_id)

    def _fail(self, message: str, details: dict[str, Any] | None = None) -> RuleResult:
        """Convenience method to return a failing result."""
        return RuleResult(
            passed=False,
            rule_id=self.rule_id,
            message=message,
            severity=self.severity,
            details=details or {},
        )
