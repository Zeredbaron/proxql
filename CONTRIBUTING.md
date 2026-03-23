# Contributing to ProxQL

Thanks for your interest in contributing! ProxQL welcomes contributions from everyone — whether you're fixing a typo, adding a security rule, or building a new integration.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Zeredbaron/proxql.git
cd proxql

# Python setup
cd packages/python
pip install -e ".[dev]"
pytest -v

# TypeScript setup
cd packages/typescript
npm install
npx vitest run
```

## What to Work On

Check the [open issues](https://github.com/Zeredbaron/proxql/issues) for things to work on. Issues labeled `good first issue` are a great starting point.

Areas where contributions are especially welcome:

- **Security rules** — New detection patterns for emerging SQL threats
- **SQL dialect coverage** — Test and fix validation for specific dialects (Snowflake, BigQuery, Redshift, etc.)
- **Integration examples** — Django, Express, SQLAlchemy, Prisma, FastAPI middleware, etc.
- **Performance** — Profiling and optimizing the validation pipeline
- **Documentation** — Improving clarity, adding examples, fixing typos
- **Bug fixes** — Especially with reproduction test cases

## Development Workflow

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure tests pass in both Python and TypeScript
4. If adding a feature, add tests (use shared test fixtures when possible)
5. Open a pull request

## Dual-Language Parity

ProxQL ships as both a Python and TypeScript package. When adding features or fixing bugs:

- **Both implementations should stay in sync.** If you add a rule in Python, add the equivalent in TypeScript (or note in your PR that the other side needs follow-up).
- **Shared test fixtures** live in `shared/test-cases/` as JSON files. Both implementations consume these, so adding test cases there gives you coverage in both languages for free.

## Adding a Security Rule

1. **Python**: Create a new file in `packages/python/proxql/rules/`, subclass `Rule` from `base.py`, and register it in `registry.py`
2. **TypeScript**: Add the equivalent in `packages/typescript/src/rules/`
3. **Tests**: Add JSON test cases in `shared/test-cases/security-rules/`
4. **Assign a severity**: CRITICAL, HIGH, MEDIUM, or LOW (see existing rules for guidance)

## Code Style

- **Python**: We use `ruff` for linting and `mypy` in strict mode for type checking. All public APIs need type annotations.
- **TypeScript**: Strict `tsconfig.json`. Explicit types on exports.
- **Formatting**: Run `ruff check .` (Python) and `npx tsc --noEmit` (TypeScript) before submitting.

## Running CI Locally

```bash
# Python — full CI check
cd packages/python
ruff check .          # Lint
mypy proxql           # Type check
pytest -v --tb=short  # Tests

# TypeScript — full CI check
cd packages/typescript
npx tsc --noEmit      # Type check
npx vitest run        # Tests
npx tsup src/index.ts --format cjs,esm --dts --clean  # Build
```

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Update documentation if the public API changes
- Reference any related issues in the PR description

## Reporting Issues

- **Bugs**: Include the SQL query that caused the issue, the expected behavior, and the actual behavior. Include your Python/Node version and ProxQL version.
- **Feature requests**: Describe the use case and why existing functionality doesn't cover it.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
