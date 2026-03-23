# ProxQL - Copilot Instructions

ProxQL is a SQL validation library that blocks destructive queries from LLM-generated SQL. It acts as a firewall between AI agents and databases: parse the query, check it against policies, reject if unsafe.

## Project Structure

This is a **dual-language monorepo** with identical APIs in Python and TypeScript:

```
packages/
  python/          # Python package (sqlglot-based parser)
    proxql/        # Source code
    tests/         # pytest tests
  typescript/      # TypeScript/JS package (node-sql-parser)
    src/           # Source code
    dist/          # Built output (CJS + ESM + .d.ts)
shared/
  test-cases/      # JSON test fixtures shared across both implementations
```

## Architecture

Validation runs in 4 phases, each optional and short-circuiting on failure:

1. **Policy** (`policy.py` / `validator.ts`) — checks statement type (SELECT/INSERT/etc.) and table allowlists
2. **Security** (`security.py`, `rules/`) — deep AST analysis for injection patterns (13 rules, severity-ranked)
3. **Limits** (`limits.py` / `limits.ts`) — row limit enforcement (max_rows, require_limit)
4. **Cost** (`cost.py` / `cost.ts`) — query complexity estimation (JOINs, subqueries, missing WHERE, etc.)

Key design choices:
- Pure in-memory parsing, zero network calls, ~200µs per validation
- Python uses `sqlglot` for parsing (20+ SQL dialects). TypeScript uses `node-sql-parser`.
- Security rules are registered via a singleton `RuleRegistry` pattern
- Both packages export the same public API: `validate()`, `is_safe()`, `Validator` class

## Conventions

- **Python**: strict mypy, ruff linting, pytest. Python 3.10+.
- **TypeScript**: strict tsconfig, vitest, tsup build (CJS/ESM/dts). Node 18+.
- Shared test cases in `shared/test-cases/*.json` must pass in both languages.
- Keep both implementations in sync — a feature added to one should be added to the other.

## Common Tasks

```bash
# Python: install + test
cd packages/python && pip install -e ".[dev]" && pytest -v

# TypeScript: install + test
cd packages/typescript && npm install && npm test

# Lint Python
cd packages/python && ruff check .

# Type check Python
cd packages/python && mypy proxql

# Type check TypeScript
cd packages/typescript && npx tsc --noEmit
```

## When Contributing

- Validate that changes pass CI in both languages
- Security rules go in `packages/python/proxql/rules/` and `packages/typescript/src/rules/`
- Add shared test cases to `shared/test-cases/` for cross-language coverage
- The `Validator` class is the main entry point — keep its API surface small
- This is a security library: be conservative. Reject ambiguous queries rather than allowing them.
