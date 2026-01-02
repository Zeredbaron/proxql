import { Parser, type AST } from 'node-sql-parser';
import { ValidationResult } from './result';
import { SecurityConfig, type SecurityConfigOptions } from './security';
import { runSecurityRules } from './rules';

/**
 * Validation mode.
 */
export type Mode = 'read_only' | 'write_safe' | 'custom';

/**
 * Options for creating a Validator.
 */
export interface ValidatorOptions {
  /** Validation mode (default: "read_only") */
  mode?: Mode;
  /** Optional list of table names that can be accessed */
  allowedTables?: string[];
  /** For custom mode: statements to allow */
  allowedStatements?: string[];
  /** For custom mode: statements to block */
  blockedStatements?: string[];
  /** SQL dialect for parsing */
  dialect?: string;
  /** Security rule configuration (true/false/SecurityConfig/SecurityConfigOptions) */
  securityConfig?: boolean | SecurityConfig | SecurityConfigOptions;
}

// Statement types allowed in each mode
const READ_ONLY_ALLOWED = new Set(['SELECT']);
const WRITE_SAFE_ALLOWED = new Set(['SELECT', 'INSERT', 'UPDATE']);
const WRITE_SAFE_BLOCKED = new Set([
  'DELETE',
  'DROP',
  'TRUNCATE',
  'ALTER',
  'CREATE',
  'GRANT',
  'REVOKE',
]);

/**
 * SQL query validator.
 *
 * For repeated validations with the same configuration, create a Validator
 * instance rather than calling validate() each time.
 *
 * @example
 * ```typescript
 * const validator = new Validator({
 *   mode: "read_only",
 *   allowedTables: ["products", "categories"]
 * });
 *
 * validator.validate("SELECT * FROM products").isSafe  // true
 * validator.validate("SELECT * FROM users").isSafe     // false
 * ```
 */
export class Validator {
  private readonly mode: Mode;
  private readonly allowedTables: Set<string> | null;
  private readonly allowedStatements: Set<string> | null;
  private readonly blockedStatements: Set<string> | null;
  private readonly dialect: string;
  private readonly securityConfig: SecurityConfig | null;
  private readonly parser: Parser;

  constructor(options: ValidatorOptions = {}) {
    this.mode = options.mode ?? 'read_only';
    this.dialect = options.dialect ?? 'postgresql';
    this.parser = new Parser();

    // Handle allowed tables (case-insensitive)
    if (options.allowedTables) {
      this.allowedTables = new Set(options.allowedTables.map((t) => t.toLowerCase()));
    } else {
      this.allowedTables = null;
    }

    // Handle security config
    if (options.securityConfig === false) {
      this.securityConfig = null;
    } else if (options.securityConfig === true || options.securityConfig === undefined) {
      this.securityConfig = new SecurityConfig();
    } else if (options.securityConfig instanceof SecurityConfig) {
      this.securityConfig = options.securityConfig;
    } else {
      // Plain object passed - convert to SecurityConfig
      this.securityConfig = new SecurityConfig(options.securityConfig);
    }

    // Initialize statement rules based on mode
    this.allowedStatements = this.initAllowedStatements(options);
    this.blockedStatements = this.initBlockedStatements(options);
  }

  private initAllowedStatements(options: ValidatorOptions): Set<string> | null {
    switch (this.mode) {
      case 'read_only':
        return READ_ONLY_ALLOWED;
      case 'write_safe':
        return WRITE_SAFE_ALLOWED;
      case 'custom':
        if (options.allowedStatements) {
          return new Set(options.allowedStatements.map((s) => s.toUpperCase()));
        }
        return null;
      default:
        return READ_ONLY_ALLOWED;
    }
  }

  private initBlockedStatements(options: ValidatorOptions): Set<string> | null {
    switch (this.mode) {
      case 'read_only':
        return null; // read_only uses allowlist only
      case 'write_safe':
        return WRITE_SAFE_BLOCKED;
      case 'custom':
        if (options.blockedStatements) {
          return new Set(options.blockedStatements.map((s) => s.toUpperCase()));
        }
        return null;
      default:
        return null;
    }
  }

  /**
   * Validate a SQL query.
   */
  validate(sql: string): ValidationResult {
    // Check for empty/whitespace-only queries
    if (!sql || !sql.trim()) {
      return ValidationResult.unsafe('Query is empty or contains only whitespace');
    }

    try {
      // Parse the SQL
      const ast = this.parser.astify(sql, { database: this.mapDialect(this.dialect) });
      const statements = Array.isArray(ast) ? ast : [ast];

      if (statements.length === 0) {
        return ValidationResult.unsafe('No valid SQL statements found');
      }

      // Validate each statement
      for (const stmt of statements) {
        // 1. Check statement type
        const typeResult = this.checkStatementType(stmt);
        if (!typeResult.isSafe) return typeResult;

        // 2. Check table allowlist
        const tableResult = this.checkTables(stmt, sql);
        if (!tableResult.isSafe) return tableResult;
      }

      // 3. Run security rules (on entire query)
      if (this.securityConfig) {
        const securityResult = runSecurityRules(sql, ast, this.securityConfig);
        if (!securityResult.isSafe) return securityResult;
      }

      // All checks passed
      const firstStmt = statements[0] ?? null;
      return ValidationResult.safe({
        statementType: this.getStatementType(firstStmt),
        tables: this.extractAllTables(statements),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return ValidationResult.unsafe(`SQL parse error: ${message}`);
    }
  }

  private mapDialect(dialect: string): string {
    // Map common dialect names to node-sql-parser database names
    const dialectMap: Record<string, string> = {
      postgres: 'postgresql',
      postgresql: 'postgresql',
      mysql: 'mysql',
      sqlite: 'sqlite',
      snowflake: 'snowflake',
      bigquery: 'bigquery',
      redshift: 'redshift',
      hive: 'hive',
      spark: 'spark',
      trino: 'trino',
      presto: 'trino',
      flinksql: 'flinksql',
      transactsql: 'transactsql',
      mssql: 'transactsql',
      sqlserver: 'transactsql',
    };
    return dialectMap[dialect.toLowerCase()] ?? 'postgresql';
  }

  private getStatementType(stmt: AST | null): string {
    if (!stmt) return 'UNKNOWN';
    // node-sql-parser uses 'type' for the statement type
    return (stmt as any).type?.toUpperCase() ?? 'UNKNOWN';
  }

  private checkStatementType(stmt: AST): ValidationResult {
    const stmtType = this.getStatementType(stmt);

    // Check blocklist first (blocked takes precedence)
    if (this.blockedStatements?.has(stmtType)) {
      return ValidationResult.unsafe(
        `Statement type '${stmtType}' is blocked in ${this.mode} mode`
      );
    }

    // Check allowlist
    if (this.allowedStatements && !this.allowedStatements.has(stmtType)) {
      return ValidationResult.unsafe(
        `Statement type '${stmtType}' is not allowed in ${this.mode} mode`
      );
    }

    return ValidationResult.safe();
  }

  private checkTables(stmt: AST, _sql: string): ValidationResult {
    if (!this.allowedTables) return ValidationResult.safe();

    const tables = this.extractTables(stmt);

    for (const table of tables) {
      const tableLower = table.toLowerCase();
      if (!this.allowedTables.has(tableLower)) {
        return ValidationResult.unsafe(
          `Table '${table}' is not in allowed tables list`
        );
      }
    }

    return ValidationResult.safe();
  }

  private extractTables(stmt: AST): string[] {
    const tables: string[] = [];
    this.walkAst(stmt, (node: any) => {
      // Handle table references
      if (node && typeof node === 'object') {
        // Direct table reference
        if (node.table && typeof node.table === 'string') {
          tables.push(node.table);
        }
        // FROM clause with array of tables
        if (Array.isArray(node.from)) {
          for (const item of node.from) {
            if (item?.table) tables.push(item.table);
          }
        }
      }
    });
    return [...new Set(tables)]; // Deduplicate
  }

  private extractAllTables(statements: AST[]): string[] {
    const allTables: string[] = [];
    for (const stmt of statements) {
      allTables.push(...this.extractTables(stmt));
    }
    return [...new Set(allTables)];
  }

  private walkAst(node: any, callback: (node: any) => void): void {
    if (!node || typeof node !== 'object') return;

    callback(node);

    if (Array.isArray(node)) {
      for (const item of node) {
        this.walkAst(item, callback);
      }
    } else {
      for (const key of Object.keys(node)) {
        this.walkAst(node[key], callback);
      }
    }
  }
}

