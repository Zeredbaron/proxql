<p align="center">
  <h1 align="center">ProxQL</h1>
  <p align="center">
    <strong>The Firewall for AI Agents</strong>
  </p>
  <p align="center">
    Stop your LLM from dropping tables, leaking PII, or melting your database.
  </p>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#why-proxql">Why ProxQL</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## The Problem

You're building an AI agent that talks to your database. Cool. But what happens when:

- Your agent hallucinates and runs `DROP TABLE users`?
- It queries `SELECT * FROM employees` and leaks salaries to unauthorized users?
- It writes a cartesian join that scans 10 billion rows and freezes production?

**ProxQL sits between your AI and your database.** Every query gets validated before it touches your data.

## Installation

```bash
pip install proxql
```

## Quick Start

```python
import proxql

# Create a validator with your policy
validator = proxql.Validator(
    mode="read_only",  # Only allow SELECT statements
    allowed_tables=["products", "categories", "reviews"]
)

# Validate queries from your AI agent
result = validator.validate("SELECT * FROM products WHERE id = 1")
print(result.is_safe)  # True

result = validator.validate("DROP TABLE users")
print(result.is_safe)   # False
print(result.reason)    # "Blocked: DROP statements are not allowed"

result = validator.validate("SELECT * FROM employees")
print(result.is_safe)   # False
print(result.reason)    # "Blocked: Table 'employees' is not in allowed_tables"
```

## Features

### Query Validation
- **Syntax checking** — Catch malformed SQL before it hits your DB
- **Statement filtering** — Block `DROP`, `DELETE`, `TRUNCATE`, `ALTER`
- **Table allowlisting** — Restrict access to specific tables
- **Read-only mode** — Only permit `SELECT` statements

### Modes

| Mode | Allowed Statements |
|------|-------------------|
| `read_only` | `SELECT` only |
| `write_safe` | `SELECT`, `INSERT`, `UPDATE` (no destructive ops) |
| `custom` | Define your own policy |

### Coming Soon
- Column-level permissions
- Row-level security policies  
- Query complexity analysis (prevent expensive joins)
- PII detection and redaction

## Why ProxQL?

> "You wouldn't give a junior intern root access to production. Why are you giving it to a hallucinating AI?"

Every AI agent framework (LangChain, CrewAI, AutoGen) lets you connect to databases. None of them protect you from what the AI might do once connected.

ProxQL is the missing safety layer.

## Usage with LangChain

```python
from langchain_community.utilities import SQLDatabase
import proxql

# Wrap your database connection
db = SQLDatabase.from_uri("postgresql://localhost/mydb")
validator = proxql.Validator(mode="read_only")

def safe_query(query: str) -> str:
    result = validator.validate(query)
    if not result.is_safe:
        raise ValueError(f"Query blocked: {result.reason}")
    return db.run(query)
```

## API Reference

### `proxql.Validator`

```python
Validator(
    mode: str = "read_only",           # "read_only" | "write_safe" | "custom"
    allowed_tables: list[str] = None,  # Whitelist of accessible tables
    blocked_statements: list[str] = None,  # Additional statements to block
    dialect: str = "postgres"          # SQL dialect for parsing
)
```

### `Validator.validate(query: str) -> ValidationResult`

```python
ValidationResult(
    is_safe: bool,      # Whether the query passed validation
    reason: str | None, # Explanation if blocked
    parsed: dict        # AST representation of the query
)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Clone the repo
git clone https://github.com/Zeredbaron/proxql.git
cd proxql

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built for the agentic future 🤖
</p>
