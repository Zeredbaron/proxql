import { describe, it, expect } from 'vitest';
import { validate, isSafe, Validator, ValidationResult } from '../index';
import { SecurityConfig, RuleSeverity } from '../security';

describe('Simple API', () => {
  it('allows SELECT', () => {
    const result = validate('SELECT * FROM users');
    expect(result.isSafe).toBe(true);
    expect(result.statementType).toBe('SELECT');
  });

  it('blocks DROP TABLE', () => {
    const result = validate('DROP TABLE users');
    expect(result.isSafe).toBe(false);
    expect(result.reason).toContain('DROP');
  });

  it('blocks DELETE', () => {
    const result = validate('DELETE FROM users WHERE id = 1');
    expect(result.isSafe).toBe(false);
    expect(result.reason).toContain('DELETE');
  });

  it('blocks INSERT', () => {
    const result = validate("INSERT INTO users (name) VALUES ('test')");
    expect(result.isSafe).toBe(false);
    expect(result.reason).toContain('INSERT');
  });

  it('blocks UPDATE', () => {
    const result = validate("UPDATE users SET name = 'test' WHERE id = 1");
    expect(result.isSafe).toBe(false);
    expect(result.reason).toContain('UPDATE');
  });

  it('isSafe() returns boolean', () => {
    expect(isSafe('SELECT * FROM users')).toBe(true);
    expect(isSafe('DROP TABLE users')).toBe(false);
  });
});

describe('Read-Only Mode', () => {
  const validator = new Validator({ mode: 'read_only' });

  it('allows simple SELECT', () => {
    const result = validator.validate('SELECT * FROM products');
    expect(result.isSafe).toBe(true);
  });

  it('allows SELECT with JOIN', () => {
    const result = validator.validate(
      'SELECT * FROM products p JOIN categories c ON p.category_id = c.id'
    );
    expect(result.isSafe).toBe(true);
  });

  it('allows SELECT with subquery', () => {
    const result = validator.validate('SELECT * FROM (SELECT id, name FROM users) AS t');
    expect(result.isSafe).toBe(true);
  });

  it('blocks TRUNCATE', () => {
    const result = validator.validate('TRUNCATE TABLE users');
    expect(result.isSafe).toBe(false);
  });
});

describe('Write-Safe Mode', () => {
  const validator = new Validator({ mode: 'write_safe' });

  it('allows SELECT', () => {
    expect(validator.validate('SELECT * FROM users').isSafe).toBe(true);
  });

  it('allows INSERT', () => {
    expect(validator.validate("INSERT INTO users (name) VALUES ('test')").isSafe).toBe(true);
  });

  it('allows UPDATE', () => {
    expect(validator.validate("UPDATE users SET name = 'test' WHERE id = 1").isSafe).toBe(true);
  });

  it('blocks DELETE', () => {
    expect(validator.validate('DELETE FROM users WHERE id = 1').isSafe).toBe(false);
  });

  it('blocks DROP', () => {
    expect(validator.validate('DROP TABLE users').isSafe).toBe(false);
  });

  it('blocks TRUNCATE', () => {
    expect(validator.validate('TRUNCATE TABLE users').isSafe).toBe(false);
  });
});

describe('Table Allowlist', () => {
  const validator = new Validator({
    mode: 'read_only',
    allowedTables: ['products', 'categories'],
  });

  it('allows whitelisted table', () => {
    expect(validator.validate('SELECT * FROM products').isSafe).toBe(true);
  });

  it('blocks non-whitelisted table', () => {
    const result = validator.validate('SELECT * FROM users');
    expect(result.isSafe).toBe(false);
    expect(result.reason).toContain('users');
  });

  it('case insensitive', () => {
    expect(validator.validate('SELECT * FROM PRODUCTS').isSafe).toBe(true);
  });
});

describe('Edge Cases', () => {
  it('blocks empty query', () => {
    expect(validate('').isSafe).toBe(false);
  });

  it('blocks whitespace-only query', () => {
    expect(validate('   \n\t  ').isSafe).toBe(false);
  });

  it('handles comments', () => {
    expect(validate('SELECT * FROM users /* DROP TABLE users */').isSafe).toBe(true);
  });

  it('case insensitive keywords', () => {
    expect(validate('select * from users').isSafe).toBe(true);
    expect(validate('SeLeCt * FrOm users').isSafe).toBe(true);
  });
});

describe('Security Rules', () => {
  it('blocks xp_cmdshell by default', () => {
    const result = validate("SELECT xp_cmdshell('whoami')");
    expect(result.isSafe).toBe(false);
  });

  it('can disable security rules', () => {
    const result = validate("SELECT xp_cmdshell('whoami')", { security: false });
    expect(result.isSafe).toBe(true);
  });

  it('blocks pg_read_file', () => {
    const result = validate("SELECT pg_read_file('/etc/passwd')");
    expect(result.isSafe).toBe(false);
  });

  it('detects hex-encoded keywords', () => {
    const validator = new Validator({
      mode: 'read_only',
      securityConfig: new SecurityConfig({ minimumSeverity: RuleSeverity.MEDIUM }),
    });
    // 0x44524F50 = 'DROP'
    const result = validator.validate('SELECT 0x44524F50');
    expect(result.isSafe).toBe(false);
    expect(result.reason?.toLowerCase()).toContain('hex');
  });
});

describe('ValidationResult', () => {
  it('toString() works', () => {
    const safe = ValidationResult.safe({ statementType: 'SELECT' });
    expect(safe.toString()).toContain('safe');

    const unsafe = ValidationResult.unsafe('blocked');
    expect(unsafe.toString()).toContain('unsafe');
  });
});



