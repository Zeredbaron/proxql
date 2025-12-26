<p align="center">
  <img src="https://img.shields.io/badge/🛡️-ProxQL-blue?style=for-the-badge&labelColor=000" alt="ProxQL" height="40">
</p>

<h1 align="center">The Database Firewall for AI Agents</h1>

<p align="center">
  <strong>Validate SQL queries before they touch your data.<br>Block destructive statements. Detect injection patterns. Sleep at night.</strong>
</p>

<p align="center">
  <a href="https://github.com/zeredbaron/proxql/actions"><img src="https://github.com/zeredbaron/proxql/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/proxql/"><img src="https://img.shields.io/pypi/v/proxql?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/proxql"><img src="https://img.shields.io/npm/v/proxql?color=blue&label=npm" alt="npm"></a>
  <a href="https://github.com/zeredbaron/proxql/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  <a href="https://github.com/zeredbaron/proxql/stargazers"><img src="https://img.shields.io/github/stars/zeredbaron/proxql?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#security-rules">Security</a> •
  <a href="#integrations">Integrations</a>
</p>

---

## The Problem

You're building an AI agent that talks to your database. But what happens when:

| Scenario | Risk |
|----------|------|
| 🔥 LLM hallucinates | `DROP TABLE users` — goodbye data |
| 🔓 Prompt injection | `SELECT * FROM employees` — salary leak |
| 💸 Bad query | Cartesian join scanning 10B rows — $$$$ |
| 🐛 Subtle attack | `SELECT 0x44524F50` — hex-encoded DROP |

**There's nothing between the LLM and your database.**

```
User → LLM → SQL → Database  ← no validation!
```

ProxQL fixes this:

```
User → LLM → SQL → ProxQL → Database
                      ↓
                   blocked
```

---

## Installation

<table>
<tr>
<td>

**Python**
```bash
pip install proxql
```

</td>
<td>

**TypeScript / JavaScript**
```bash
npm install proxql
```

</td>
</tr>
</table>

---

## Quick Start

### Python

```python
import proxql

# ✓ Safe queries pass
proxql.is_safe("SELECT * FROM users")              # True

# ✗ Dangerous queries blocked
result = proxql.validate("DROP TABLE users")
result.is_safe   # False
result.reason    # "Statement type 'DROP' is not allowed"

# ✗ Table restrictions enforced
result = proxql.validate(
    "SELECT * FROM salaries",
    allowed_tables=["products", "orders"]
)
result.is_safe   # False
result.reason    # "Table 'salaries' is not in allowed tables list"
```

### TypeScript

```typescript
import proxql from 'proxql';

// ✓ Safe queries pass
proxql.isSafe("SELECT * FROM users")              // true

// ✗ Dangerous queries blocked
const result = proxql.validate("DROP TABLE users");
result.isSafe   // false
result.reason   // "Statement type 'DROP' is not allowed"

// ✗ Table restrictions enforced
const result = proxql.validate(
    "SELECT * FROM salaries",
    { allowedTables: ["products", "orders"] }
);
result.isSafe   // false
```

---

## Features

### 🛡️ Three Validation Modes

| Mode | Allowed Statements | Use Case |
|------|-------------------|----------|
| `read_only` | `SELECT` only | Analytics, dashboards, read-only agents |
| `write_safe` | `SELECT`, `INSERT`, `UPDATE` | CRUD apps (blocks destructive ops) |
| `custom` | You define | Full control |

```python
from proxql import Validator

# Read-only for analytics agents
analyst = Validator(mode="read_only")

# Allow writes but block DROP/DELETE/TRUNCATE
api = Validator(mode="write_safe")

# Custom rules
admin = Validator(
    mode="custom",
    allowed_statements=["SELECT", "INSERT"],
    blocked_statements=["DROP"]
)
```

### 📋 Table Allowlists

Restrict queries to specific tables — even in subqueries, CTEs, and JOINs:

```python
validator = Validator(
    mode="read_only",
    allowed_tables=["products", "categories", "reviews"]
)

# Blocked — tries to access unauthorized table in subquery
validator.validate("""
    SELECT * FROM (SELECT * FROM secret_table) AS t
""").is_safe  # False
```

### 🗄️ Multi-Dialect Support

ProxQL uses [sqlglot](https://sqlglot.com/) under the hood, supporting 20+ SQL dialects:

```python
from proxql import Validator

pg = Validator(mode="read_only", dialect="postgres")
mysql = Validator(mode="read_only", dialect="mysql")
snow = Validator(mode="read_only", dialect="snowflake")
```

**Supported:** PostgreSQL, MySQL, SQLite, Snowflake, BigQuery, Redshift, DuckDB, Presto, Trino, Spark, and more.

---

## Security Rules

Beyond statement types, ProxQL includes **13 security rules** to detect SQL injection patterns:

### 🔴 Critical Severity

| Rule | What It Catches |
|------|-----------------|
| `file-access` | `INTO OUTFILE`, `LOAD DATA INFILE`, `pg_read_file()`, `COPY` |
| `system-command` | `xp_cmdshell`, `xp_regread`, OLE automation |
| `dynamic-sql` | `EXEC`, `EXECUTE`, `PREPARE`, `sp_executesql` |
| `privilege-escalation` | `CREATE USER`, `ALTER USER`, `GRANT`, `SET ROLE` |

### 🟡 High Severity

| Rule | What It Catches |
|------|-----------------|
| `stored-procedure` | `CALL` statements |
| `unicode-obfuscation` | Cyrillic/Greek homoglyphs (е vs e, а vs a) |

### 🟠 Medium Severity

| Rule | What It Catches |
|------|-----------------|
| `dangerous-functions` | `SLEEP()`, `pg_sleep()`, `BENCHMARK()`, `WAITFOR` |
| `hex-encoding` | `0x44524F50` (spells DROP) |
| `char-function` | `CHAR(68,82,79,80)` (spells DROP) |
| `string-concat` | `'DR' \|\| 'OP'` concatenation attacks |
| `transaction-abuse` | `LOCK TABLE` (DoS vector) |

### 🟢 Low Severity

| Rule | What It Catches |
|------|-----------------|
| `metadata-access` | `information_schema`, `pg_catalog`, `mysql.user` |
| `schema-commands` | `SHOW TABLES`, `DESCRIBE`, `EXPLAIN` |

### Configure Security Rules

```python
from proxql import Validator, SecurityConfig, RuleSeverity

# Default: HIGH+ severity blocks queries
validator = Validator(mode="read_only")

# Paranoid mode: block everything
validator = Validator(
    mode="read_only",
    security_config=SecurityConfig(
        minimum_severity=RuleSeverity.LOW,
        fail_on_low=True
    )
)

# Disable specific rules
validator = Validator(
    mode="read_only",
    security_config=SecurityConfig(
        disabled_rules={"metadata-access", "schema-commands"}
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
validator = Validator(mode="read_only")

def safe_query(query: str) -> str:
    result = validator.validate(query)
    if not result.is_safe:
        raise ValueError(f"Query blocked: {result.reason}")
    return db.run(query)

# Use safe_query instead of db.run in your agent
```

### FastAPI

```python
from fastapi import FastAPI, HTTPException
from proxql import Validator

app = FastAPI()
validator = Validator(mode="read_only", allowed_tables=["products"])

@app.post("/query")
async def run_query(query: str):
    result = validator.validate(query)
    if not result.is_safe:
        raise HTTPException(400, f"Blocked: {result.reason}")
    return execute_query(query)
```

### Raw Database Drivers

```python
import psycopg2
from proxql import Validator

conn = psycopg2.connect("...")
validator = Validator(mode="read_only")

def execute_safe(cursor, query: str):
    if not validator.validate(query).is_safe:
        raise ValueError("Query blocked")
    return cursor.execute(query)
```

---

## Performance

```
⏱️  ~200 µs per validation
🚀 5,000+ queries/second
```

Pure in-memory parsing with sqlglot — no network calls, no database round-trips.

---

## Edge Cases Handled

ProxQL correctly detects tables and patterns in:

- ✅ **Subqueries:** `SELECT * FROM (SELECT * FROM secret) AS t`
- ✅ **CTEs:** `WITH temp AS (SELECT * FROM secret) SELECT * FROM temp`
- ✅ **JOINs:** `SELECT * FROM a JOIN b ON ...`
- ✅ **Multi-statement:** `SELECT 1; DROP TABLE users;`
- ✅ **Comments:** `SELECT * /* DROP TABLE */ FROM users`
- ✅ **Case variations:** `drop TABLE Users`
- ✅ **Hex encoding:** `0x44524F50` (decodes to DROP)
- ✅ **CHAR() abuse:** `CHAR(68,82,79,80)` (spells DROP)

---

## Why ProxQL?

> **"You wouldn't give a junior intern root access to production. Why are you giving it to a hallucinating AI?"**

Every AI framework (LangChain, LlamaIndex, CrewAI, AutoGen) lets you connect to databases. **None of them protect you from what the AI might do once connected.**

ProxQL is the missing safety layer.

---

## Repository Structure

```
proxql/
├── packages/
│   ├── python/          # pip install proxql
│   └── typescript/      # npm install proxql
├── shared/
│   └── test-cases/      # Cross-language test fixtures
└── README.md
```

Both packages run identical test suites to ensure behavioral parity.

---

## Contributing

```bash
# Python
cd packages/python
pip install -e ".[dev]"
pytest

# TypeScript
cd packages/typescript
npm install
npm test
```

PRs welcome! Especially for:
- New SQL injection patterns
- Additional dialect edge cases
- Documentation improvements

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built for the agentic future 🤖</strong>
  <br><br>
  <a href="https://github.com/zeredbaron/proxql">⭐ Star on GitHub</a> •
  <a href="https://pypi.org/project/proxql/">PyPI</a> •
  <a href="https://www.npmjs.com/package/proxql">npm</a>
</p>
