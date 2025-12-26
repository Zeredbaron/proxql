"""Rule registry for discovering and managing security rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Rule, RuleSeverity

if TYPE_CHECKING:
    pass


class RuleRegistry:
    """Central registry for security rules.

    Provides rule discovery, filtering, and management.
    Rules are registered automatically when their modules are imported.

    Example:
        registry = RuleRegistry()
        registry.register(FileAccessRule())
        registry.register(DynamicSQLRule())

        # Get all rules
        all_rules = registry.all()

        # Get only critical rules
        critical = registry.by_severity(RuleSeverity.CRITICAL)
    """

    _instance: RuleRegistry | None = None

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    @classmethod
    def get_instance(cls) -> RuleRegistry:
        """Get the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, rule: Rule) -> None:
        """Register a rule with the registry.

        Args:
            rule: The rule instance to register

        Raises:
            ValueError: If a rule with the same ID is already registered
        """
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule '{rule.rule_id}' is already registered")
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> None:
        """Remove a rule from the registry."""
        self._rules.pop(rule_id, None)

    def get(self, rule_id: str) -> Rule | None:
        """Get a rule by its ID."""
        return self._rules.get(rule_id)

    def all(self) -> list[Rule]:
        """Get all registered rules."""
        return list(self._rules.values())

    def by_severity(self, severity: RuleSeverity) -> list[Rule]:
        """Get rules filtered by severity level."""
        return [r for r in self._rules.values() if r.severity == severity]

    def by_severity_minimum(self, minimum: RuleSeverity) -> list[Rule]:
        """Get rules with severity >= the specified minimum.

        Severity order: CRITICAL > HIGH > MEDIUM > LOW
        """
        severity_order = {
            RuleSeverity.CRITICAL: 4,
            RuleSeverity.HIGH: 3,
            RuleSeverity.MEDIUM: 2,
            RuleSeverity.LOW: 1,
        }
        min_level = severity_order[minimum]
        return [r for r in self._rules.values() if severity_order[r.severity] >= min_level]

    def clear(self) -> None:
        """Clear all registered rules (mainly for testing)."""
        self._rules.clear()


def _ensure_rules_loaded() -> None:
    """Ensure all rule modules are imported and rules are registered."""
    # Import all rule modules to trigger registration
    from . import (  # noqa: F401
        dangerous_functions,
        dangerous_statements,
        file_access,
        metadata_access,
        obfuscation,
    )


def get_all_rules() -> list[Rule]:
    """Get all registered security rules."""
    _ensure_rules_loaded()
    return RuleRegistry.get_instance().all()


def get_rules_by_severity(severity: RuleSeverity) -> list[Rule]:
    """Get rules filtered by severity level."""
    _ensure_rules_loaded()
    return RuleRegistry.get_instance().by_severity(severity)
