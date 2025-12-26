<p align="center">
  <h1 align="center">ProxQL</h1>
  <p align="center">
    <strong>A 50-line firewall to stop your AI from dropping tables</strong>
  </p>
</p>

<p align="center">
  <a href="https://pypi.org/project/proxql/"><img src="https://img.shields.io/pypi/v/proxql?color=blue" alt="PyPI"></a>
  <a href="https://github.com/zeredbaron/proxql/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/pypi/pyversions/proxql" alt="Python"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#modes">Modes</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#integrations">Integrations</a>
</p>

---

## The Problem

You're building an AI agent that talks to your database. But what happens when:

- 🔥 Your LLM hallucinates and runs `DROP TABLE users`
- 🔓 It queries `SELECT * FROM employees` and leaks salaries
- 💸 It writes a cartesian join that scans 10 billion rows

**ProxQL validates every query before it touches your data.**

## Installation

```bash
pip install proxql
```

## Quick Start

```python
import proxql

# ✓ Safe queries pass
proxql.validate("SELECT * FROM users").is_safe  # True
proxql.is_safe("SELECT * FROM products")        # True

# ✗ Dangerous queries are blocked
result = proxql.validate("DROP TABLE users")
result.is_safe   # False
result.reason    # "Statement type 'DROP' is not allowed in read_only mode"

# ✗ Unauthorized tables are blocked
result = proxql.validate(
    "SELECT * FROM employees",
    allowed_tables=["products", "categories"]
)
result.is_safe   # False
result.reason    # "Table 'employees' is not in allowed tables list"
```

## Modes

| Mode | Allowed Statements | Use Case |
|------|-------------------|----------|
| `read_only` | `SELECT` only | Analytics, reporting, read-only agents |
| `write_safe` | `SELECT`, `INSERT`, `UPDATE` | CRUD operations (no destructive ops) |
| `custom` | You define | Full control over allowed/blocked statements |

### Read-Only Mode (Default)

```python
import proxql

# Only SELECT statements pass
proxql.is_safe("SELECT * FROM users")           # True
proxql.is_safe("INSERT INTO logs VALUES (1)")   # False
proxql.is_safe("DELETE FROM users")             # False
proxql.is_safe("DROP TABLE users")              # False
```

### Write-Safe Mode

```python
from proxql import Validator

validator = Validator(mode="write_safe")

validator.validate("SELECT * FROM users").is_safe    # True
validator.validate("INSERT INTO users ...").is_safe  # True
validator.validate("UPDATE users SET ...").is_safe   # True
validator.validate("DELETE FROM users").is_safe      # False  (blocked)
validator.validate("DROP TABLE users").is_safe       # False  (blocked)
validator.validate("TRUNCATE TABLE users").is_safe   # False  (blocked)
```

### Custom Mode

```python
from proxql import Validator

# Allow only specific statements
validator = Validator(
    mode="custom",
    allowed_statements=["SELECT", "INSERT"],
)
validator.validate("SELECT * FROM users").is_safe  # True
validator.validate("INSERT INTO logs ...").is_safe # True
validator.validate("UPDATE users SET ...").is_safe # False

# Or block specific statements
validator = Validator(
    mode="custom",
    blocked_statements=["DROP", "TRUNCATE"],
)
validator.validate("SELECT * FROM users").is_safe  # True
validator.validate("DROP TABLE users").is_safe     # False
```

## Table Allowlist

Restrict queries to specific tables:

```python
from proxql import Validator

validator = Validator(
    mode="read_only",
    allowed_tables=["products", "categories", "reviews"]
)

validator.validate("SELECT * FROM products").is_safe      # True
validator.validate("SELECT * FROM employees").is_safe     # False

# Also detects tables in subqueries, CTEs, and JOINs
validator.validate("""
    SELECT * FROM (SELECT * FROM secret_table) AS t
""").is_safe  # False - secret_table detected in subquery
```

## SQL Dialect Support

ProxQL uses [sqlglot](https://sqlglot.com/) under the hood, supporting 20+ SQL dialects:

```python
from proxql import Validator

# PostgreSQL
pg_validator = Validator(mode="read_only", dialect="postgres")
pg_validator.validate("SELECT * FROM users LIMIT 10 OFFSET 5")

# MySQL
mysql_validator = Validator(mode="read_only", dialect="mysql")
mysql_validator.validate("SELECT * FROM users LIMIT 5, 10")

# Snowflake, BigQuery, DuckDB, etc.
```

Supported dialects: `postgres`, `mysql`, `sqlite`, `snowflake`, `bigquery`, `redshift`, `duckdb`, `presto`, `trino`, `spark`, and more.

## API Reference

### `proxql.validate(sql, *, mode, allowed_tables, dialect)`

Validate a SQL query string.

```python
proxql.validate(
    sql: str,                              # The SQL query to validate
    *,
    mode: str = "read_only",               # "read_only" | "write_safe" | "custom"
    allowed_tables: list[str] | None = None,  # Optional table whitelist
    dialect: str | None = None,            # SQL dialect (auto-detected if None)
) -> ValidationResult
```

### `proxql.is_safe(sql, **kwargs)`

Convenience wrapper that returns just the boolean result.

```python
proxql.is_safe("SELECT * FROM users")  # True
proxql.is_safe("DROP TABLE users")     # False
```

### `proxql.Validator`

For repeated validations, create a Validator instance:

```python
from proxql import Validator

validator = Validator(
    mode: str = "read_only",               # Validation mode
    allowed_tables: list[str] | None = None,  # Table whitelist
    allowed_statements: list[str] | None = None,  # For custom mode
    blocked_statements: list[str] | None = None,  # For custom mode
    dialect: str | None = None,            # SQL dialect
)

result = validator.validate(sql: str) -> ValidationResult
```

### `ValidationResult`

```python
@dataclass(frozen=True)
class ValidationResult:
    is_safe: bool                    # Whether the query passed validation
    reason: str | None = None        # Explanation if blocked
    statement_type: str | None = None  # SELECT, INSERT, DROP, etc.
    tables: list[str] = []           # Tables referenced in query

    def __bool__(self) -> bool:      # Can use in boolean context
        return self.is_safe
```

## Integrations

### LangChain

```python
from langchain_community.utilities import SQLDatabase
from proxql import Validator

db = SQLDatabase.from_uri("postgresql://localhost/mydb")
validator = Validator(mode="read_only")

def safe_query(query: str) -> str:
    result = validator.validate(query)
    if not result.is_safe:
        raise ValueError(f"Query blocked: {result.reason}")
    return db.run(query)

# Use safe_query instead of db.run in your agent
```

### Raw Database Drivers

```python
import psycopg2
from proxql import Validator

conn = psycopg2.connect("...")
validator = Validator(mode="read_only", allowed_tables=["products"])

def execute_safe(cursor, query: str):
    result = validator.validate(query)
    if not result.is_safe:
        raise ValueError(f"Blocked: {result.reason}")
    return cursor.execute(query)
```

### FastAPI Middleware

```python
from fastapi import FastAPI, HTTPException
from proxql import Validator

app = FastAPI()
validator = Validator(mode="read_only")

@app.post("/query")
async def run_query(query: str):
    result = validator.validate(query)
    if not result.is_safe:
        raise HTTPException(400, f"Query blocked: {result.reason}")
    # Execute query...
```

## Edge Cases Handled

ProxQL correctly detects:

- **Subqueries**: `SELECT * FROM (SELECT * FROM secret_table) AS t`
- **CTEs**: `WITH temp AS (SELECT * FROM secret) SELECT * FROM temp`
- **JOINs**: `SELECT * FROM a JOIN b ON ...` — checks all tables
- **Multi-statement**: `SELECT 1; DROP TABLE users;` — blocks if any unsafe
- **Comments**: `SELECT * /* DROP TABLE */ FROM users` — comments ignored
- **Case sensitivity**: `drop TABLE Users` normalized correctly

## Why ProxQL?

> "You wouldn't give a junior intern root access to production. Why are you giving it to a hallucinating AI?"

Every AI framework (LangChain, CrewAI, AutoGen) lets you connect to databases. None of them protect you from what the AI might do once connected.

**ProxQL is the missing safety layer.**

## Contributing

```bash
git clone https://github.com/zeredbaron/proxql.git
cd proxql
pip install -e ".[dev]"
pytest
```

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built for the agentic future 🤖
</p>
