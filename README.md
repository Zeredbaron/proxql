<p align="center">
  <h1 align="center">ProxQL</h1>
  <p align="center">
    <strong>The Database Firewall for AI Agents</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/zeredbaron/proxql/actions"><img src="https://github.com/zeredbaron/proxql/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/proxql/"><img src="https://img.shields.io/pypi/v/proxql?color=blue" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/proxql"><img src="https://img.shields.io/npm/v/proxql?color=blue" alt="npm"></a>
  <a href="https://github.com/zeredbaron/proxql/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
</p>

---

## The Problem

You're building an AI agent that talks to your database. But what happens when:

- 🔥 Your LLM hallucinates and runs `DROP TABLE users`
- 🔓 It queries `SELECT * FROM employees` and leaks salaries
- 💸 It writes a cartesian join that scans 10 billion rows

**ProxQL validates every query before it touches your data.**

## Installation

### Python

```bash
pip install proxql
```

### TypeScript/JavaScript

```bash
npm install proxql
```

## Quick Start

### Python

```python
import proxql

# ✓ Safe queries pass
proxql.validate("SELECT * FROM users").is_safe  # True
proxql.is_safe("SELECT * FROM products")        # True

# ✗ Dangerous queries are blocked
result = proxql.validate("DROP TABLE users")
result.is_safe   # False
result.reason    # "Statement type 'DROP' is not allowed in read_only mode"
```

### TypeScript

```typescript
import proxql from 'proxql';

// ✓ Safe queries pass
proxql.validate("SELECT * FROM users").isSafe  // true
proxql.isSafe("SELECT * FROM products")        // true

// ✗ Dangerous queries are blocked
const result = proxql.validate("DROP TABLE users");
result.isSafe   // false
result.reason   // "Statement type 'DROP' is not allowed in read_only mode"
```

## Packages

| Package | Language | Installation |
|---------|----------|--------------|
| [`proxql`](./packages/python) | Python | `pip install proxql` |
| [`proxql`](./packages/typescript) | TypeScript/JS | `npm install proxql` |

## Modes

| Mode | Allowed Statements | Use Case |
|------|-------------------|----------|
| `read_only` | `SELECT` only | Analytics, reporting, read-only agents |
| `write_safe` | `SELECT`, `INSERT`, `UPDATE` | CRUD operations (no destructive ops) |
| `custom` | You define | Full control over allowed/blocked statements |

## Security Rules

Beyond statement types and table allowlists, ProxQL includes 13 security rules to detect SQL injection patterns:

| Rule ID | Severity | What It Detects |
|---------|----------|-----------------|
| `file-access` | 🔴 CRITICAL | `INTO OUTFILE`, `LOAD DATA INFILE`, `pg_read_file()` |
| `system-command` | 🔴 CRITICAL | `xp_cmdshell`, `xp_regread` |
| `dynamic-sql` | 🔴 CRITICAL | `EXEC`, `EXECUTE`, `PREPARE` |
| `privilege-escalation` | 🔴 CRITICAL | `CREATE USER`, `ALTER USER`, `SET ROLE` |
| `stored-procedure` | 🟡 HIGH | `CALL` statements |
| `unicode-obfuscation` | 🟡 HIGH | Cyrillic/Greek chars masquerading as ASCII |
| `dangerous-functions` | 🟠 MEDIUM | `SLEEP()`, `pg_sleep()`, `BENCHMARK()` |
| `hex-encoding` | 🟠 MEDIUM | Hex literals hiding SQL keywords |
| `char-function` | 🟠 MEDIUM | `CHAR(68,82,79,80)` spelling DROP |
| `string-concat` | 🟠 MEDIUM | `'DR' || 'OP'` concatenation attacks |
| `transaction-abuse` | 🟠 MEDIUM | `LOCK TABLE` (DoS vector) |
| `metadata-access` | 🟢 LOW | `information_schema`, system tables |
| `schema-commands` | 🟢 LOW | `SHOW TABLES`, `DESCRIBE` |

## Repository Structure

```
proxql/
├── packages/
│   ├── python/          # Python package (pip install proxql)
│   └── typescript/      # TypeScript package (npm install proxql)
├── shared/
│   └── test-cases/      # Shared test fixtures for cross-language parity
└── README.md
```

## Why ProxQL?

> "You wouldn't give a junior intern root access to production. Why are you giving it to a hallucinating AI?"

Every AI framework (LangChain, CrewAI, AutoGen) lets you connect to databases. None of them protect you from what the AI might do once connected.

**ProxQL is the missing safety layer.**

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

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built for the agentic future 🤖
</p>
