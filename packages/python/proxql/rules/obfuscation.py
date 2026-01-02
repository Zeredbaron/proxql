"""Rule for detecting SQL obfuscation techniques."""

from __future__ import annotations

import contextlib
import re
from typing import TYPE_CHECKING

from sqlglot import exp

from .base import Rule, RuleResult, RuleSeverity
from .registry import RuleRegistry

if TYPE_CHECKING:
    from sqlglot.expressions import Expression


class HexEncodingRule(Rule):
    """Detects hex-encoded strings that might hide malicious content.

    Attackers use hex encoding (0x44524F50 = 'DROP') to bypass
    keyword-based filters. This rule detects suspiciously long
    hex literals that might contain encoded SQL.

    MEDIUM severity - hex literals are sometimes legitimate, but
    long ones are suspicious.
    """

    @property
    def rule_id(self) -> str:
        return "hex-encoding"

    @property
    def name(self) -> str:
        return "Hex Encoding Detection"

    @property
    def description(self) -> str:
        return (
            "Detects hex-encoded string literals that might be used to hide malicious SQL keywords."
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
        """Check for suspicious hex encoding."""

        # Get raw SQL from context if available, otherwise use expr.sql()
        # (expr.sql() may transform hex literals during parsing)
        raw_sql = str(context.get("raw_sql", "")) or expr.sql()

        # Look for hex literals: 0x followed by hex digits
        # Flag if they're suspiciously long (could encode meaningful text)
        hex_pattern = r"0x[0-9A-Fa-f]{8,}"  # 8+ hex chars = 4+ ASCII chars

        matches = re.findall(hex_pattern, raw_sql, re.IGNORECASE)
        for match in matches:
            # Decode and check if it looks like SQL keywords
            try:
                hex_value = match[2:]  # Remove '0x' prefix
                if len(hex_value) % 2 == 0:
                    decoded = bytes.fromhex(hex_value).decode("ascii", errors="ignore")
                    # Check for SQL keywords in decoded text
                    sql_keywords = [
                        "DROP",
                        "DELETE",
                        "INSERT",
                        "UPDATE",
                        "SELECT",
                        "TRUNCATE",
                        "ALTER",
                        "CREATE",
                        "EXEC",
                        "UNION",
                    ]
                    decoded_upper = decoded.upper()
                    for kw in sql_keywords:
                        if kw in decoded_upper:
                            return self._fail(
                                f"Hex-encoded SQL keyword detected: '{decoded}' contains '{kw}'",
                                {
                                    "pattern": "hex_encoded_sql",
                                    "hex_value": match,
                                    "decoded": decoded,
                                },
                            )
            except (ValueError, UnicodeDecodeError):
                pass  # Not valid hex/ASCII, ignore

        return self._pass()


class CharFunctionRule(Rule):
    """Detects CHAR() function abuse for string construction.

    Attackers use CHAR(68,82,79,80) to spell 'DROP' character by character,
    bypassing keyword filters. This rule detects multiple CHAR() calls
    that could be constructing SQL keywords.

    MEDIUM severity - CHAR() is legitimate for single characters,
    but multiple calls are suspicious.
    """

    @property
    def rule_id(self) -> str:
        return "char-function"

    @property
    def name(self) -> str:
        return "CHAR() Function Abuse Detection"

    @property
    def description(self) -> str:
        return (
            "Detects abuse of CHAR() function to construct strings "
            "character-by-character to evade keyword filters."
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
        """Check for CHAR() abuse."""

        char_calls: list[exp.Anonymous | exp.Chr] = []

        # Find all CHAR() function calls
        for func in expr.find_all(exp.Anonymous):
            func_name = func.name.lower() if func.name else ""
            if func_name in ("char", "chr"):
                char_calls.append(func)

        # Also check for built-in Char expressions
        for chr_func in expr.find_all(exp.Chr):
            char_calls.append(chr_func)

        # If there are multiple CHAR calls, try to decode them
        if len(char_calls) >= 3:  # 3+ chars might spell something
            # Try to extract the character codes
            codes = self._extract_char_codes(char_calls)

            if len(codes) >= 3:
                # Try to decode as string
                try:
                    decoded = "".join(chr(c) for c in codes if 32 <= c < 127)
                    sql_keywords = [
                        "DROP",
                        "DELETE",
                        "INSERT",
                        "UPDATE",
                        "SELECT",
                        "TRUNCATE",
                        "ALTER",
                        "CREATE",
                        "EXEC",
                        "UNION",
                    ]
                    decoded_upper = decoded.upper()
                    for kw in sql_keywords:
                        if kw in decoded_upper:
                            return self._fail(
                                f"CHAR()-constructed SQL keyword detected: '{decoded}'",
                                {
                                    "pattern": "char_constructed_sql",
                                    "char_codes": codes,
                                    "decoded": decoded,
                                },
                            )
                except (ValueError, OverflowError):
                    pass

        return self._pass()

    def _extract_char_codes(self, char_calls: list[exp.Anonymous | exp.Chr]) -> list[int]:
        """Extract numeric character codes from CHAR() function calls."""
        codes: list[int] = []
        for call in char_calls:
            # Try to get the numeric argument
            if hasattr(call, "expressions") and call.expressions:
                for arg in call.expressions:
                    if isinstance(arg, exp.Literal) and arg.is_number:
                        with contextlib.suppress(ValueError, TypeError):
                            codes.append(int(arg.this))
            elif hasattr(call, "this") and isinstance(call.this, exp.Literal):
                with contextlib.suppress(ValueError, TypeError):
                    codes.append(int(call.this.this))
        return codes


class StringConcatRule(Rule):
    """Detects string concatenation that might build SQL dynamically.

    Concatenating strings like 'DR' || 'OP' can evade keyword detection.
    This rule looks for suspicious concatenation patterns.

    LOW severity - string concatenation is very common and legitimate.
    Only flags when it looks like SQL keyword construction.
    """

    @property
    def rule_id(self) -> str:
        return "string-concat"

    @property
    def name(self) -> str:
        return "String Concatenation Detection"

    @property
    def description(self) -> str:
        return (
            "Detects string concatenation patterns that might be used "
            "to construct SQL keywords dynamically."
        )

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM  # Elevated from LOW - concat is often malicious

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for suspicious string concatenation."""

        # Find CONCAT functions and || operators
        concat_strings: list[str] = []

        # Check for Concat expressions
        for concat in expr.find_all(exp.Concat):
            for literal in concat.find_all(exp.Literal):
                if literal.is_string:
                    concat_strings.append(str(literal.this))

        # Check for DPipe (||) operator - need to get direct children
        for dpipe in expr.find_all(exp.DPipe):
            # Get the left and right operands
            if isinstance(dpipe.this, exp.Literal) and dpipe.this.is_string:
                concat_strings.append(str(dpipe.this.this))
            if hasattr(dpipe, "expression"):
                right = dpipe.expression
                if isinstance(right, exp.Literal) and right.is_string:
                    concat_strings.append(str(right.this))

        # If we found concatenated strings, check what they spell
        if len(concat_strings) >= 2:
            combined = "".join(concat_strings).upper()
            sql_keywords = ["DROP", "DELETE", "TRUNCATE", "ALTER", "EXEC"]

            for kw in sql_keywords:
                if kw in combined:
                    return self._fail(
                        f"String concatenation builds SQL keyword: '{kw}'",
                        {
                            "pattern": "concat_constructed_sql",
                            "parts": concat_strings,
                            "combined": combined,
                        },
                    )

        return self._pass()


class UnicodeObfuscationRule(Rule):
    """Detects Unicode homoglyph attacks.

    Attackers can use Cyrillic or other Unicode characters that look
    like ASCII letters to bypass keyword detection:
    - Cyrillic 'а' (U+0430) looks like Latin 'a'
    - Cyrillic 'е' (U+0435) looks like Latin 'e'

    HIGH severity - this is definitely an attack attempt.
    """

    @property
    def rule_id(self) -> str:
        return "unicode-obfuscation"

    @property
    def name(self) -> str:
        return "Unicode Homoglyph Detection"

    @property
    def description(self) -> str:
        return (
            "Detects Unicode characters that look like ASCII letters but "
            "are from different scripts (homoglyph attacks)."
        )

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(
        self,
        expr: Expression,
        dialect: str | None = None,
        **context: object,
    ) -> RuleResult:
        """Check for Unicode homoglyphs."""

        # Get raw SQL from context if available (preserves Unicode chars)
        raw_sql = str(context.get("raw_sql", "")) or expr.sql()

        # Common homoglyphs used in attacks (Cyrillic characters that look like Latin)
        homoglyph_map = {
            "\u0430": "a",  # Cyrillic а
            "\u0435": "e",  # Cyrillic е
            "\u043e": "o",  # Cyrillic о
            "\u0440": "p",  # Cyrillic р
            "\u0441": "c",  # Cyrillic с
            "\u0443": "y",  # Cyrillic у (looks like y in some fonts)
            "\u0445": "x",  # Cyrillic х
            "\u0455": "s",  # Cyrillic ѕ
            "\u0456": "i",  # Cyrillic і
            "\u0458": "j",  # Cyrillic ј
            "\u04bb": "h",  # Cyrillic һ
            "\u04c0": "l",  # Cyrillic Ӏ (palochka)
            # Greek characters
            "\u03bf": "o",  # Greek ο (omicron)
            "\u03b1": "a",  # Greek α (alpha)
            # Full-width characters
            "\uff33": "S",  # Fullwidth S
            "\uff45": "e",  # Fullwidth e
        }

        found_homoglyphs = []
        for char, latin_equiv in homoglyph_map.items():
            if char in raw_sql:
                found_homoglyphs.append((char, latin_equiv, hex(ord(char))))

        if found_homoglyphs:
            return self._fail(
                "Unicode homoglyphs detected - possible keyword obfuscation",
                {
                    "pattern": "unicode_homoglyph",
                    "homoglyphs": [
                        {"char": h[0], "looks_like": h[1], "codepoint": h[2]}
                        for h in found_homoglyphs
                    ],
                },
            )

        return self._pass()


# Register all rules
_registry = RuleRegistry.get_instance()
_registry.register(HexEncodingRule())
_registry.register(CharFunctionRule())
_registry.register(StringConcatRule())
_registry.register(UnicodeObfuscationRule())
