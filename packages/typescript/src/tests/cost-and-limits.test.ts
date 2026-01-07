import { describe, it, expect } from 'vitest';
import { Validator, CostEstimator, CostLevel, LimitEnforcer, isLimitOk } from '../index';
import { Parser, type AST } from 'node-sql-parser';

describe('CostEstimation', () => {
  const parser = new Parser();
  const estimator = new CostEstimator();

  const parse = (sql: string): AST => {
    const ast = parser.astify(sql, { database: 'postgresql' });
    const result = Array.isArray(ast) ? ast[0] : ast;
    if (!result) throw new Error('Failed to parse SQL');
    return result;
  };

  it('should estimate low cost for simple SELECT', () => {
    const ast = parse('SELECT id, name FROM users WHERE id = 1');
    const cost = estimator.estimate(ast);
    expect(cost.level).toBe(CostLevel.LOW);
  });

  it('should detect SELECT *', () => {
    const ast = parse('SELECT * FROM users');
    const cost = estimator.estimate(ast);
    expect(cost.factors).toContain('SELECT * (all columns)');
  });

  it('should detect missing WHERE', () => {
    const ast = parse('SELECT id FROM users');
    const cost = estimator.estimate(ast);
    expect(cost.factors).toContain('SELECT without WHERE clause');
  });

  it('should detect JOINs', () => {
    const ast = parse(`
      SELECT * FROM users u
      JOIN orders o ON u.id = o.user_id
      JOIN products p ON o.product_id = p.id
    `);
    const cost = estimator.estimate(ast);
    expect(cost.level).toBeGreaterThanOrEqual(CostLevel.MEDIUM);
    expect(cost.factors.some((f) => f.includes('JOIN'))).toBe(true);
  });

  it('should detect ORDER BY without LIMIT', () => {
    const ast = parse('SELECT * FROM users ORDER BY created_at');
    const cost = estimator.estimate(ast);
    expect(cost.factors).toContain('ORDER BY without LIMIT');
  });

  it('should not penalize ORDER BY with LIMIT', () => {
    const ast = parse('SELECT * FROM users ORDER BY created_at LIMIT 10');
    const cost = estimator.estimate(ast);
    expect(cost.factors).not.toContain('ORDER BY without LIMIT');
  });
});

describe('CostInValidator', () => {
  it('should return cost when estimateCost is enabled', () => {
    const validator = new Validator({ mode: 'read_only', estimateCost: true });
    const result = validator.validate('SELECT * FROM users');
    expect(result.isSafe).toBe(true);
    expect(result.cost).toBeDefined();
    expect(result.cost?.level).toBeDefined();
  });

  it('should block high cost queries when blockHighCost is enabled', () => {
    const validator = new Validator({ mode: 'read_only', blockHighCost: true });

    // Simple query should pass
    const simple = validator.validate('SELECT id FROM users WHERE id = 1 LIMIT 10');
    expect(simple.isSafe).toBe(true);

    // Complex query should fail
    const complex = validator.validate(`
      SELECT * FROM a
      JOIN b ON a.id = b.a_id
      JOIN c ON b.id = c.b_id
      JOIN d ON c.id = d.c_id
      JOIN e ON d.id = e.d_id
      ORDER BY a.created_at
    `);
    expect(complex.isSafe).toBe(false);
    expect(complex.reason?.toLowerCase()).toContain('cost');
  });

  it('should accept maxCostLevel as string', () => {
    const validator = new Validator({ mode: 'read_only', maxCostLevel: 'LOW' });
    const result = validator.validate('SELECT * FROM users');
    expect(result.isSafe).toBe(false);
  });

  it('should add warnings for high cost queries when not blocked', () => {
    const validator = new Validator({ mode: 'read_only', estimateCost: true });
    const result = validator.validate(`
      SELECT * FROM a
      JOIN b ON a.id = b.a_id
      JOIN c ON b.id = c.b_id
      JOIN d ON c.id = d.c_id
      JOIN e ON d.id = e.d_id
    `);
    expect(result.isSafe).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings.some((w) => w.toLowerCase().includes('cost'))).toBe(true);
  });
});

describe('LimitEnforcement', () => {
  const parser = new Parser();

  const parse = (sql: string): AST => {
    const ast = parser.astify(sql, { database: 'postgresql' });
    const result = Array.isArray(ast) ? ast[0] : ast;
    if (!result) throw new Error('Failed to parse SQL');
    return result;
  };

  it('should pass query with valid limit', () => {
    const enforcer = new LimitEnforcer({ maxRows: 1000 });
    const ast = parse('SELECT * FROM users LIMIT 100');
    const result = enforcer.check(ast);
    expect(isLimitOk(result)).toBe(true);
    expect(result.limitValue).toBe(100);
  });

  it('should fail query exceeding max rows', () => {
    const enforcer = new LimitEnforcer({ maxRows: 1000 });
    const ast = parse('SELECT * FROM users LIMIT 5000');
    const result = enforcer.check(ast);
    expect(isLimitOk(result)).toBe(false);
    expect(result.exceedsMax).toBe(true);
  });

  it('should pass query without limit when not required', () => {
    const enforcer = new LimitEnforcer({ maxRows: 1000 });
    const ast = parse('SELECT * FROM users');
    const result = enforcer.check(ast);
    expect(isLimitOk(result)).toBe(true);
    expect(result.hasLimit).toBe(false);
  });

  it('should fail query without limit when required', () => {
    const enforcer = new LimitEnforcer({ requireLimit: true });
    const ast = parse('SELECT * FROM users');
    const result = enforcer.check(ast);
    expect(isLimitOk(result)).toBe(false);
    expect(result.reason).toContain('LIMIT');
  });
});

describe('LimitInValidator', () => {
  it('should block excessive limits', () => {
    const validator = new Validator({ mode: 'read_only', maxRows: 1000 });

    const valid = validator.validate('SELECT * FROM users LIMIT 100');
    expect(valid.isSafe).toBe(true);
    expect(valid.limitValue).toBe(100);

    const invalid = validator.validate('SELECT * FROM users LIMIT 5000');
    expect(invalid.isSafe).toBe(false);
    expect(invalid.reason).toContain('5000');
  });

  it('should require limit when requireLimit is set', () => {
    const validator = new Validator({ mode: 'read_only', requireLimit: true });

    const withLimit = validator.validate('SELECT * FROM users LIMIT 100');
    expect(withLimit.isSafe).toBe(true);

    const withoutLimit = validator.validate('SELECT * FROM users');
    expect(withoutLimit.isSafe).toBe(false);
    expect(withoutLimit.reason).toContain('LIMIT');
  });

  it('should work with both maxRows and requireLimit', () => {
    const validator = new Validator({
      mode: 'read_only',
      maxRows: 1000,
      requireLimit: true,
    });

    // No limit - blocked
    expect(validator.validate('SELECT * FROM users').isSafe).toBe(false);

    // Limit too high - blocked
    expect(validator.validate('SELECT * FROM users LIMIT 5000').isSafe).toBe(false);

    // Valid limit - passes
    expect(validator.validate('SELECT * FROM users LIMIT 500').isSafe).toBe(true);
  });
});

describe('CombinedFeatures', () => {
  it('should work with all features enabled', () => {
    const validator = new Validator({
      mode: 'read_only',
      maxRows: 1000,
      requireLimit: true,
      estimateCost: true,
      maxCostLevel: CostLevel.MEDIUM,
    });

    // Good query passes
    const good = validator.validate('SELECT id, name FROM users WHERE id = 1 LIMIT 10');
    expect(good.isSafe).toBe(true);
    expect(good.cost).toBeDefined();
    expect(good.limitValue).toBe(10);

    // Missing limit fails
    expect(validator.validate('SELECT id FROM users WHERE id = 1').isSafe).toBe(false);

    // High cost fails
    const highCost = validator.validate(`
      SELECT * FROM a
      JOIN b ON a.id = b.a_id
      JOIN c ON b.id = c.b_id
      JOIN d ON c.id = d.c_id
      LIMIT 10
    `);
    expect(highCost.isSafe).toBe(false);
    expect(highCost.reason?.toLowerCase()).toContain('cost');
  });

  it('should not affect simple API by default', () => {
    const validator = new Validator({ mode: 'read_only' });
    const result = validator.validate('SELECT * FROM users');
    expect(result.isSafe).toBe(true);
    expect(result.cost).toBeUndefined();
    expect(result.limitValue).toBeUndefined();
  });
});
