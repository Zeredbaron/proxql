"""Security rules module for ProxQL.

This module provides a composable, extensible rule system for detecting
dangerous SQL patterns beyond simple statement type checking.

Architecture:
    - Rule: Protocol defining the interface for all security rules
    - RuleResult: Structured result from rule evaluation
    - RuleRegistry: Central registry for rule discovery and management
    - Individual rule classes: Implement specific security checks

Usage:
    from proxql.rules import get_all_rules, RuleSeverity

    rules = get_all_rules()
    for rule in rules:
        result = rule.check(parsed_sql, dialect="postgres")
        if not result.passed:
            print(f"[{result.severity}] {result.message}")
"""

from .base import Rule, RuleResult, RuleSeverity
from .registry import RuleRegistry, get_all_rules, get_rules_by_severity

__all__ = [
    "Rule",
    "RuleResult",
    "RuleSeverity",
    "RuleRegistry",
    "get_all_rules",
    "get_rules_by_severity",
]
