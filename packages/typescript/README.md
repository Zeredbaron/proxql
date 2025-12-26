# ProxQL (TypeScript)

**The Database Firewall for AI Agents**

A SQL validation library that blocks destructive queries from LLM-generated SQL.

## Installation

```bash
npm install proxql
# or
yarn add proxql
# or
pnpm add proxql
```

## Quick Start

```typescript
import proxql from 'proxql';

// ✓ Safe queries pass
proxql.validate("SELECT * FROM users").isSafe  // true
proxql.isSafe("SELECT * FROM products")        // true

// ✗ Dangerous queries are blocked
const result = proxql.validate("DROP TABLE users");
result.isSafe   // false
result.reason   // "Statement type 'DROP' is not allowed in read_only mode"

// ✗ Unauthorized tables are blocked
const result2 = proxql.validate("SELECT * FROM employees", {
  allowedTables: ["products", "categories"]
});
result2.isSafe   // false
result2.reason   // "Table 'employees' is not in allowed tables list"
```

## Modes

| Mode | Allowed Statements | Use Case |
|------|-------------------|----------|
| `read_only` | `SELECT` only | Analytics, reporting, read-only agents |
| `write_safe` | `SELECT`, `INSERT`, `UPDATE` | CRUD operations (no destructive ops) |
| `custom` | You define | Full control over allowed/blocked statements |

### Read-Only Mode (Default)

```typescript
import { validate, isSafe } from 'proxql';

// Only SELECT statements pass
isSafe("SELECT * FROM users")           // true
isSafe("INSERT INTO logs VALUES (1)")   // false
isSafe("DELETE FROM users")             // false
isSafe("DROP TABLE users")              // false
```

### Write-Safe Mode

```typescript
import { Validator } from 'proxql';

const validator = new Validator({ mode: "write_safe" });

validator.validate("SELECT * FROM users").isSafe    // true
validator.validate("INSERT INTO users ...").isSafe  // true
validator.validate("UPDATE users SET ...").isSafe   // true
validator.validate("DELETE FROM users").isSafe      // false (blocked)
validator.validate("DROP TABLE users").isSafe       // false (blocked)
```

### Custom Mode

```typescript
import { Validator } from 'proxql';

// Allow only specific statements
const validator = new Validator({
  mode: "custom",
  allowedStatements: ["SELECT", "INSERT"],
});

validator.validate("SELECT * FROM users").isSafe  // true
validator.validate("INSERT INTO logs ...").isSafe // true
validator.validate("UPDATE users SET ...").isSafe // false
```

## Security Rules

ProxQL includes 13 security rules to detect SQL injection patterns:

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

### Configuring Security Rules

```typescript
import { Validator, SecurityConfig, RuleSeverity } from 'proxql';

// Default: Only HIGH+ severity rules block queries
const validator = new Validator({ mode: "read_only" });

// More sensitive: Include MEDIUM severity
const strictValidator = new Validator({
  mode: "read_only",
  securityConfig: new SecurityConfig({
    minimumSeverity: RuleSeverity.MEDIUM
  })
});

// Disable security rules entirely
const fastValidator = new Validator({
  mode: "read_only",
  securityConfig: false
});
```

## API Reference

### `validate(sql, options?)`

```typescript
import { validate } from 'proxql';

const result = validate(sql, {
  mode: "read_only",              // "read_only" | "write_safe" | "custom"
  allowedTables: ["products"],    // Optional table whitelist
  dialect: "postgres",            // SQL dialect
  security: true,                 // true | false | SecurityConfig
});
```

### `isSafe(sql, options?)`

```typescript
import { isSafe } from 'proxql';

if (isSafe(query)) {
  executeQuery(query);
}
```

### `Validator`

```typescript
import { Validator } from 'proxql';

const validator = new Validator({
  mode: "read_only",
  allowedTables: ["products", "categories"],
  dialect: "postgres",
});

const result = validator.validate("SELECT * FROM products");
```

### `ValidationResult`

```typescript
interface ValidationResult {
  isSafe: boolean;           // Whether the query passed validation
  reason?: string;           // Explanation if blocked
  statementType?: string;    // SELECT, INSERT, DROP, etc.
  tables: string[];          // Tables referenced in query
}
```

## License

Apache License 2.0

---

See the [main ProxQL repository](https://github.com/zeredbaron/proxql) for more details.

