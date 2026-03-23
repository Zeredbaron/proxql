# AGENTS.md — Instructions for AI Coding Agents

This file provides context for AI coding agents (GitHub Copilot, Claude, Cursor, Cline, Devin, OpenHands, SWE-Agent, etc.) working on ProxQL.

## What is ProxQL?

ProxQL is a SQL validation library that acts as a firewall between AI agents and databases. It parses SQL queries and validates them against configurable policies before execution. Available for both Python and TypeScript/JavaScript.

- **PyPI**: `pip install proxql`
- **npm**: `npm install proxql`
- **License**: Apache 2.0

## Repository Structure

```
proxql/
├── packages/
│   ├── python/                 # Python implementation
│   │   ├── proxql/             # Main package
│   │   │   ├── __init__.py     # Public API: validate(), is_safe(), Validator
│   │   │   ├── validator.py    # Core Validator class (entry point)
│   │   │   ├── parser.py       # SQL parsing via sqlglot
│   │   │   ├── policy.py       # Mode enforcement (read_only, write_safe, custom)
│   │   │   ├── security.py     # Security rule coordinator
│   │   │   ├── cost.py         # Query cost estimation
│   │   │   ├── limits.py       # Row limit enforcement
│   │   │   ├── result.py       # ValidationResult dataclass
│   │   │   ├── exceptions.py   # ProxQLError, ParseError, ConfigurationError
│   │   │   └── rules/          # Security rule definitions
│   │   │       ├── base.py     # Rule base class + RuleSeverity enum
│   │   │       ├── registry.py # Singleton rule registry
│   │   │       ├── dangerous_statements.py
│   │   │       ├── dangerous_functions.py
│   │   │       ├── file_access.py
│   │   │       ├── metadata_access.py
│   │   │       └── obfuscation.py
│   │   ├── tests/              # pytest test suite
│   │   ├── examples/           # Integration examples (LangChain)
│   │   └── pyproject.toml      # Build config (hatchling)
│   │
│   └── typescript/             # TypeScript implementation
│       ├── src/                # Source (mirrors Python API)
│       │   ├── index.ts        # Public API: validate(), isSafe(), Validator
│       │   ├── validator.ts    # Core Validator class
│       │   ├── security.ts     # Security rules
│       │   ├── cost.ts         # Cost estimation
│       │   ├── limits.ts       # Row limits
│       │   ├── result.ts       # ValidationResult type
│       │   └── rules/          # Rule definitions
│       ├── package.json        # npm config
│       ├── tsconfig.json
│       └── vitest.config.ts    # Test config
│
├── shared/
│   └── test-cases/             # Cross-language test fixtures (JSON)
│       ├── read-only-mode.json
│       ├── write-safe-mode.json
│       ├── table-allowlist.json
│       ├── edge-cases.json
│       ├── security-config.json
│       └── security-rules/     # Per-rule test data
│
├── .github/
│   └── workflows/ci.yml       # CI: Python 3.10-3.13 + Node 20
│
├── README.md                   # User-facing documentation
├── CONTRIBUTING.md             # How to contribute
├── AGENTS.md                   # This file
└── LICENSE                     # Apache 2.0
```

## Architecture

The validation pipeline runs in 4 phases, each independently configurable:

1. **Policy** (`policy.py`) — Checks statement type against the mode (read_only/write_safe/custom) and validates tables against an allowlist
2. **Security** (`security.py` + `rules/`) — Deep AST analysis for dangerous patterns (file access, dynamic SQL, obfuscation, etc.). Rules are registered via a singleton `RuleRegistry` and filtered by severity
3. **Limits** (`limits.py`) — Enforces max row counts and requires LIMIT clauses
4. **Cost** (`cost.py`) — Estimates query complexity (JOINs, subqueries, missing WHERE, etc.) and classifies as LOW/MEDIUM/HIGH/EXTREME

Key dependency: Python uses [sqlglot](https://sqlglot.com/) for parsing (20+ SQL dialects). TypeScript uses [node-sql-parser](https://www.npmjs.com/package/node-sql-parser).

## Development Setup

```bash
# Python
cd packages/python
pip install -e ".[dev]"
pytest -v                    # Run tests
ruff check .                 # Lint
mypy proxql                  # Type check

# TypeScript
cd packages/typescript
npm install
npx vitest run               # Run tests
npx tsc --noEmit             # Type check
```

## Code Conventions

- **Python**: Strict mypy, ruff linting, type annotations everywhere, `from __future__ import annotations`
- **TypeScript**: Strict tsconfig, explicit types on public APIs
- **Both languages**: Feature parity — if you add/change something in one, do the same in the other
- **Shared test cases**: Cross-language fixtures live in `shared/test-cases/` as JSON. Both implementations run these.
- **Rule pattern**: New security rules subclass `Rule` (Python) or implement the rule interface (TS), register via `RuleRegistry`, and get test cases in `shared/test-cases/security-rules/`

## Adding a New Security Rule

1. Create `packages/python/proxql/rules/your_rule.py` — subclass `Rule` from `rules/base.py`
2. Register it in `rules/registry.py` → `_ensure_rules_loaded()`
3. Create `packages/typescript/src/rules/` equivalent
4. Add shared test cases in `shared/test-cases/security-rules/your-rule.json`
5. Add tests in both `packages/python/tests/` and TypeScript test files

## Key Design Decisions

- **Parse errors = unsafe**: If SQL can't be parsed, validation returns `is_safe=False`
- **Multi-statement**: All statements in a multi-statement query are validated; one failure blocks all
- **No network calls**: Pure in-memory parsing, ~200µs per validation
- **Guardrail, not security solution**: ProxQL is one layer of defense, not a replacement for database permissions

## What Contributions Are Welcome

- New security rules for emerging patterns
- Additional SQL dialect testing
- Performance optimizations
- Integration examples (Django, Express, SQLAlchemy, Prisma, etc.)
- Documentation improvements
- Bug fixes with test cases

## CI

GitHub Actions runs on every push/PR to `main`:
- Python: lint (ruff) → type check (mypy) → test (pytest) across Python 3.10–3.13
- TypeScript: type check (tsc) → test (vitest) → build (tsup)
