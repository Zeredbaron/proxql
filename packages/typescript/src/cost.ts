import type { AST } from 'node-sql-parser';

/**
 * Query cost levels from low to extreme.
 */
export enum CostLevel {
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  EXTREME = 4,
}

/**
 * Estimated cost/complexity of a query.
 */
export interface CostEstimate {
  /** Overall cost level */
  level: CostLevel;
  /** Numeric complexity score (higher = more expensive) */
  score: number;
  /** Factors contributing to the cost */
  factors: string[];
}

// Scoring weights for different factors
const WEIGHTS = {
  join: 10,
  crossJoin: 50,
  subquery: 15,
  subqueryDepth: 10,
  noWhere: 20,
  aggregateNoLimit: 15,
  union: 10,
  distinct: 5,
  orderNoLimit: 15,
  wildcardSelect: 5,
};

// Thresholds for cost levels
const THRESHOLDS = {
  [CostLevel.LOW]: 20,
  [CostLevel.MEDIUM]: 50,
  [CostLevel.HIGH]: 100,
};

/**
 * Estimates query cost based on structural analysis.
 *
 * This analyzes the query AST to estimate relative cost. It does NOT
 * know about actual table sizes or indexes - it only looks at query
 * structure to identify potentially expensive patterns.
 */
export class CostEstimator {
  /**
   * Estimate the cost of a parsed SQL statement.
   */
  estimate(ast: AST): CostEstimate {
    let score = 0;
    const factors: string[] = [];

    // Count JOINs
    const joinCount = this.countJoins(ast);
    if (joinCount > 0) {
      score += joinCount * WEIGHTS.join;
      factors.push(`${joinCount} JOIN(s)`);
    }

    // Check for cross joins
    const crossJoinCount = this.countCrossJoins(ast);
    if (crossJoinCount > 0) {
      score += crossJoinCount * WEIGHTS.crossJoin;
      factors.push(`${crossJoinCount} CROSS JOIN(s) - cartesian product`);
    }

    // Check subquery depth
    const subqueryDepth = this.getSubqueryDepth(ast);
    if (subqueryDepth > 0) {
      score += WEIGHTS.subquery;
      score += subqueryDepth * WEIGHTS.subqueryDepth;
      factors.push(`Subquery depth: ${subqueryDepth}`);
    }

    // Check for missing WHERE on SELECT
    if (this.isSelectWithoutWhere(ast)) {
      score += WEIGHTS.noWhere;
      factors.push('SELECT without WHERE clause');
    }

    // Check for aggregations without limit
    if (this.hasAggregateWithoutLimit(ast)) {
      score += WEIGHTS.aggregateNoLimit;
      factors.push('Aggregate function without LIMIT');
    }

    // Check for UNION
    const unionCount = this.countUnions(ast);
    if (unionCount > 0) {
      score += unionCount * WEIGHTS.union;
      factors.push(`${unionCount} UNION operation(s)`);
    }

    // Check for DISTINCT
    if (this.hasDistinct(ast)) {
      score += WEIGHTS.distinct;
      factors.push('DISTINCT clause');
    }

    // Check for ORDER BY without LIMIT
    if (this.hasOrderWithoutLimit(ast)) {
      score += WEIGHTS.orderNoLimit;
      factors.push('ORDER BY without LIMIT');
    }

    // Check for SELECT *
    if (this.hasWildcardSelect(ast)) {
      score += WEIGHTS.wildcardSelect;
      factors.push('SELECT * (all columns)');
    }

    return {
      level: this.scoreToLevel(score),
      score,
      factors,
    };
  }

  private scoreToLevel(score: number): CostLevel {
    if (score <= THRESHOLDS[CostLevel.LOW]) return CostLevel.LOW;
    if (score <= THRESHOLDS[CostLevel.MEDIUM]) return CostLevel.MEDIUM;
    if (score <= THRESHOLDS[CostLevel.HIGH]) return CostLevel.HIGH;
    return CostLevel.EXTREME;
  }

  private countJoins(ast: AST): number {
    const stmt = ast as any;
    if (!stmt?.from || !Array.isArray(stmt.from)) return 0;

    let count = 0;
    for (const item of stmt.from) {
      if (item?.join) count++;
    }
    return count;
  }

  private countCrossJoins(ast: AST): number {
    const stmt = ast as any;
    if (!stmt?.from || !Array.isArray(stmt.from)) return 0;

    let count = 0;
    for (const item of stmt.from) {
      if (item?.join === 'CROSS') {
        count++;
      } else if (item?.join && !item?.on && !item?.using) {
        // JOIN without condition
        count++;
      }
    }
    return count;
  }

  private getSubqueryDepth(ast: AST, depth = 0): number {
    let maxDepth = depth;
    this.walkAst(ast, (node: any) => {
      if (node?.type === 'select' && depth > 0) {
        maxDepth = Math.max(maxDepth, depth);
      }
      if (node?.ast || node?.expr?.ast) {
        const subAst = node.ast ?? node.expr?.ast;
        if (subAst) {
          const subDepth = this.getSubqueryDepth(subAst, depth + 1);
          maxDepth = Math.max(maxDepth, subDepth);
        }
      }
    });
    return maxDepth;
  }

  private isSelectWithoutWhere(ast: AST): boolean {
    const stmt = ast as any;
    if (stmt?.type !== 'select') return false;
    return !stmt.where;
  }

  private hasAggregateWithoutLimit(ast: AST): boolean {
    const stmt = ast as any;
    if (stmt?.type !== 'select') return false;

    let hasAgg = false;
    this.walkAst(ast, (node: any) => {
      if (node?.type === 'aggr_func') {
        hasAgg = true;
      }
    });

    return hasAgg && !this.hasLimitClause(stmt);
  }

  private countUnions(ast: AST): number {
    const stmt = ast as any;
    if (stmt?._next?.type === 'select') {
      return 1 + this.countUnions(stmt._next);
    }
    if (stmt?.union) {
      return 1;
    }
    return 0;
  }

  private hasDistinct(ast: AST): boolean {
    const stmt = ast as any;
    if (stmt?.type !== 'select') return false;
    return stmt.distinct === 'DISTINCT';
  }

  private hasOrderWithoutLimit(ast: AST): boolean {
    const stmt = ast as any;
    if (stmt?.type !== 'select') return false;
    const hasOrder = !!stmt.orderby && stmt.orderby.length > 0;
    const hasLimit = this.hasLimitClause(stmt);
    return hasOrder && !hasLimit;
  }

  private hasLimitClause(stmt: any): boolean {
    if (!stmt.limit) return false;
    // node-sql-parser creates limit: { seperator: '', value: [] } even when no limit
    if (Array.isArray(stmt.limit.value) && stmt.limit.value.length === 0) return false;
    return true;
  }

  private hasWildcardSelect(ast: AST): boolean {
    const stmt = ast as any;
    if (stmt?.type !== 'select') return false;

    // node-sql-parser represents SELECT * with columns: '*' or columns: [{ expr: { type: 'star' }}]
    const columns = stmt.columns;
    if (columns === '*') return true;
    if (Array.isArray(columns)) {
      for (const col of columns) {
        if (col === '*') return true;
        if (col?.expr?.type === 'star') return true;
        if (col?.expr?.column === '*') return true;
      }
    }
    return false;
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

/**
 * Check if a cost estimate is acceptable (LOW or MEDIUM).
 */
export function isCostAcceptable(cost: CostEstimate): boolean {
  return cost.level <= CostLevel.MEDIUM;
}
