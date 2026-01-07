import type { CostEstimate } from './cost';

/**
 * Result of a SQL validation check.
 *
 * Can be used in boolean context:
 * ```typescript
 * const result = validate("SELECT * FROM users");
 * if (result) {
 *   // Query is safe
 * }
 * ```
 */
export class ValidationResult {
  /** Whether the query passed all validation checks */
  readonly isSafe: boolean;

  /** Explanation if the query was blocked (undefined if safe) */
  readonly reason?: string;

  /** The type of SQL statement (SELECT, INSERT, DROP, etc.) */
  readonly statementType?: string;

  /** Tables referenced in the query */
  readonly tables: string[];

  /** Estimated query cost/complexity (undefined if cost estimation disabled) */
  readonly cost?: CostEstimate;

  /** The LIMIT value if present in the query */
  readonly limitValue?: number;

  /** Non-blocking issues detected (e.g., high cost queries that passed) */
  readonly warnings: string[];

  private constructor(data: {
    isSafe: boolean;
    reason?: string;
    statementType?: string;
    tables?: string[];
    cost?: CostEstimate;
    limitValue?: number;
    warnings?: string[];
  }) {
    this.isSafe = data.isSafe;
    this.reason = data.reason;
    this.statementType = data.statementType;
    this.tables = data.tables ?? [];
    this.cost = data.cost;
    this.limitValue = data.limitValue;
    this.warnings = data.warnings ?? [];
  }

  /**
   * Create a safe validation result.
   */
  static safe(
    meta: {
      statementType?: string;
      tables?: string[];
      cost?: CostEstimate;
      limitValue?: number;
      warnings?: string[];
    } = {}
  ): ValidationResult {
    return new ValidationResult({ isSafe: true, ...meta });
  }

  /**
   * Create an unsafe validation result with a reason.
   */
  static unsafe(
    reason: string,
    meta: {
      statementType?: string;
      tables?: string[];
      cost?: CostEstimate;
      limitValue?: number;
      warnings?: string[];
    } = {}
  ): ValidationResult {
    return new ValidationResult({ isSafe: false, reason, ...meta });
  }

  /**
   * Allow using ValidationResult in boolean context.
   * Note: This is for documentation purposes; JS doesn't support operator overloading.
   * Use result.isSafe directly.
   */
  valueOf(): boolean {
    return this.isSafe;
  }

  toString(): string {
    if (this.isSafe) {
      return `ValidationResult(safe, type=${this.statementType ?? 'unknown'})`;
    }
    return `ValidationResult(unsafe, reason="${this.reason}")`;
  }
}



