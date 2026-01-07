import type { AST } from 'node-sql-parser';

/**
 * Result of checking row limits on a query.
 */
export interface LimitCheckResult {
  /** Whether the query has a LIMIT clause */
  hasLimit: boolean;
  /** The LIMIT value if present */
  limitValue?: number;
  /** Whether the limit exceeds the configured maximum */
  exceedsMax: boolean;
  /** Explanation if the check failed */
  reason?: string;
}

/**
 * Options for the LimitEnforcer.
 */
export interface LimitEnforcerOptions {
  /** Maximum allowed LIMIT value */
  maxRows?: number;
  /** If true, SELECT queries without LIMIT are rejected */
  requireLimit?: boolean;
}

/**
 * Enforces row limits on SELECT queries.
 */
export class LimitEnforcer {
  private readonly maxRows?: number;
  private readonly requireLimit: boolean;

  constructor(options: LimitEnforcerOptions = {}) {
    this.maxRows = options.maxRows;
    this.requireLimit = options.requireLimit ?? false;
  }

  /**
   * Check if a statement satisfies limit requirements.
   */
  check(ast: AST): LimitCheckResult {
    const stmt = ast as any;

    // Only check SELECT statements
    if (stmt?.type !== 'select') {
      return { hasLimit: false, exceedsMax: false };
    }

    // Extract LIMIT value
    const limitValue = this.extractLimitValue(stmt);

    if (limitValue === undefined) {
      if (this.requireLimit) {
        return {
          hasLimit: false,
          exceedsMax: false,
          reason: 'SELECT query requires a LIMIT clause',
        };
      }
      return { hasLimit: false, exceedsMax: false };
    }

    // Check against maxRows
    if (this.maxRows !== undefined && limitValue > this.maxRows) {
      return {
        hasLimit: true,
        limitValue,
        exceedsMax: true,
        reason: `LIMIT ${limitValue} exceeds maximum allowed (${this.maxRows})`,
      };
    }

    return {
      hasLimit: true,
      limitValue,
      exceedsMax: false,
    };
  }

  private extractLimitValue(stmt: any): number | undefined {
    if (!stmt.limit) return undefined;

    // node-sql-parser represents LIMIT as an array or object
    const limit = stmt.limit;

    if (Array.isArray(limit)) {
      // MySQL style: LIMIT offset, count or LIMIT count
      const countItem = limit.find((l: any) => l.type === 'number');
      if (countItem?.value !== undefined) {
        return Number(countItem.value);
      }
    } else if (typeof limit === 'object') {
      // PostgreSQL style: LIMIT { value, ... }
      if (limit.value !== undefined) {
        const val = Array.isArray(limit.value) ? limit.value[0] : limit.value;
        if (typeof val === 'number') return val;
        if (val?.type === 'number' && val?.value !== undefined) {
          return Number(val.value);
        }
      }
    }

    return undefined;
  }
}

/**
 * Check if a limit check result is OK (passed).
 */
export function isLimitOk(result: LimitCheckResult): boolean {
  return result.reason === undefined;
}
