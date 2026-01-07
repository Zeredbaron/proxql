<p align="center">
  <img src="https://img.shields.io/badge/🛤️-ProxQL-blue?style=for-the-badge&labelColor=000" alt="ProxQL" height="40">
</p>

<h1 align="center">Guardrails for AI-Generated SQL</h1>

<p align="center">
  <strong>Keep your AI agents on track.<br>Validate queries before execution. Enforce scope. Catch mistakes early.</strong>
</p>

<p align="center">
  <a href="https://github.com/zeredbaron/proxql/actions"><img src="https://github.com/zeredbaron/proxql/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/proxql/"><img src="https://img.shields.io/pypi/v/proxql?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/proxql"><img src="https://img.shields.io/npm/v/proxql?color=blue&label=npm" alt="npm"></a>
  <a href="https://github.com/zeredbaron/proxql/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#what-it-does">What It Does</a> •
  <a href="#integrations">Integrations</a>
</p>

---

## What Problem Does This Solve?

When AI agents generate SQL, you need visibility and control:

- **Scope control** — Agent should only query `products`, not `employees`
- **Operation limits** — Read-only agents shouldn't write
- **Fail fast** — Catch obvious issues before hitting the database
- **Observability** — Know what queries your agents generate

ProxQL validates queries before execution:

```
Agent → SQL → ProxQL → Database
               ↓
         ✓ allowed
         ✗ blocked (with reason)
```

> **Note:** This is one layer of defense. Proper database permissions and read-only credentials are still essential.

---

## Installation

**Python**
```bash
pip install proxql
```

**TypeScript / JavaScript**
```bash
npm install proxql
```

---

## Quick Start

```python
import proxql

# Check if a query is allowed
proxql.is_safe("SELECT * FROM users")              # True
proxql.is_safe("DROP TABLE users")                 # False

# Get details on why something was blocked
result = proxql.validate("DELETE FROM users")
result.is_safe   # False
result.reason    # "Statement type 'DELETE' is not allowed in read_only mode"

# Restrict to specific tables
result = proxql.validate(
    "SELECT * FROM salaries",
    allowed_tables=["products", "orders"]
)
result.is_safe   # False
result.reason    # "Table 'salaries' is not in allowed tables list"
```

---

## What It Does

### Operation Modes

| Mode | Allowed | Use Case |
|------|---------|----------|
| `read_only` | SELECT | Analytics, dashboards, read-only agents |
| `write_safe` | SELECT, INSERT, UPDATE | CRUD operations |
| `custom` | You define | Full control |

```python
from proxql import Validator

# Read-only for analytics
analyst = Validator(mode="read_only")

# Allow writes, block destructive ops
api = Validator(mode="write_safe")

# Custom rules
custom = Validator(
    mode="custom",
    allowed_statements=["SELECT", "INSERT"],
)
```

### Table Allowlists

Limit which tables an agent can access:

```python
validator = Validator(
    mode="read_only",
    allowed_tables=["products", "categories"]
)

# Works with subqueries, CTEs, JOINs
validator.validate("SELECT * FROM (SELECT * FROM secrets) t").is_safe  # False
```

### SQL Dialect Support

Built on [sqlglot](https://sqlglot.com/), supports 20+ dialects:

```python
Validator(dialect="postgres")
Validator(dialect="mysql")
Validator(dialect="snowflake")
# ... bigquery, redshift, duckdb, etc.
```

### Row Limits

Prevent unbounded queries:

```python
validator = Validator(
    mode="read_only",
    max_rows=1000,       # Reject LIMIT > 1000
    require_limit=True   # Reject queries without LIMIT
)

validator.validate("SELECT * FROM users").is_safe           # False - no LIMIT
validator.validate("SELECT * FROM users LIMIT 500").is_safe # True
validator.validate("SELECT * FROM users LIMIT 5000").is_safe # False - exceeds max
```

### Cost Estimation

Flag expensive queries before they hit the database:

```python
validator = Validator(
    mode="read_only",
    estimate_cost=True,
    max_cost_level="MEDIUM"  # Block HIGH/EXTREME cost queries
)

result = validator.validate("""
    SELECT * FROM orders o
    JOIN users u ON o.user_id = u.id
    JOIN products p ON o.product_id = p.id
    ORDER BY o.created_at
""")

result.cost.level    # CostLevel.HIGH
result.cost.factors  # ['2 JOIN(s)', 'ORDER BY without LIMIT', ...]
```

Cost factors detected: JOINs, cross joins, subquery depth, missing WHERE, ORDER BY without LIMIT, aggregations, UNION, SELECT *.

### Pattern Detection

Catches common issues and injection patterns:

| Pattern | Example |
|---------|---------|
| Destructive statements | `DROP`, `TRUNCATE`, `DELETE` |
| File access | `INTO OUTFILE`, `LOAD DATA INFILE` |
| Dynamic SQL | `EXEC(...)`, `PREPARE` |
| Obfuscated keywords | `0x44524F50` (hex for DROP) |
| Multi-statement injection | `SELECT 1; DROP TABLE x` |

Configure what to check:

```python
from proxql import Validator, SecurityConfig, RuleSeverity

# Strict mode
validator = Validator(
    security_config=SecurityConfig(
        minimum_severity=RuleSeverity.MEDIUM
    )
)

# Disable specific checks
validator = Validator(
    security_config=SecurityConfig(
        disabled_rules={"metadata-access"}
    )
)
```

---

## Integrations

### LangChain

```python
from langchain_community.utilities import SQLDatabase
from proxql import Validator

db = SQLDatabase.from_uri("postgresql://localhost/mydb")
validator = Validator(mode="read_only", allowed_tables=["products"])

def safe_query(query: str) -> str:
    result = validator.validate(query)
    if not result.is_safe:
        return f"Query not allowed: {result.reason}"
    return db.run(query)
```

### FastAPI

```python
from fastapi import FastAPI, HTTPException
from proxql import Validator

app = FastAPI()
validator = Validator(mode="read_only")

@app.post("/query")
async def run_query(query: str):
    result = validator.validate(query)
    if not result.is_safe:
        raise HTTPException(400, result.reason)
    return execute_query(query)
```

---

## Performance

~200µs per validation. Pure in-memory parsing, no network calls.

---

## Limitations

ProxQL is a **guardrail, not a security solution**:

- It validates query structure, not query results
- It can't prevent all malicious queries
- It's not a replacement for proper database permissions
- Use read-only database credentials for read-only agents

Think of it as a seatbelt, not a force field.

---

## Contributing

```bash
cd packages/python && pip install -e ".[dev]" && pytest
cd packages/typescript && npm install && npm test
```

---

## License

Apache 2.0

