import type { AST } from 'node-sql-parser';
import { ValidationResult } from '../result';
import { SecurityConfig, RuleSeverity } from '../security';

/**
 * Base interface for security rules.
 */
export interface Rule {
  /** Unique identifier for the rule */
  ruleId: string;
  /** Human-readable name */
  name: string;
  /** Description of what this rule detects */
  description: string;
  /** Severity level */
  severity: RuleSeverity;
  /** Check the SQL for violations */
  check(sql: string, ast: AST | AST[]): RuleViolation | null;
}

/**
 * Result of a rule check.
 */
export interface RuleViolation {
  ruleId: string;
  message: string;
  severity: RuleSeverity;
}

// ============================================================================
// Security Rules
// ============================================================================

/**
 * Detects system command execution functions.
 */
const systemCommandRule: Rule = {
  ruleId: 'system-command',
  name: 'System Command Detection',
  description: 'Detects xp_cmdshell, xp_regread, and other system command functions',
  severity: RuleSeverity.CRITICAL,
  check(sql: string): RuleViolation | null {
    const patterns = [
      /\bxp_cmdshell\s*\(/i,
      /\bxp_regread\s*\(/i,
      /\bxp_regwrite\s*\(/i,
      /\bxp_servicecontrol\s*\(/i,
      /\bsp_oacreate\s*\(/i,
      /\bsp_oamethod\s*\(/i,
    ];

    for (const pattern of patterns) {
      const match = sql.match(pattern);
      if (match) {
        const funcName = match[0].replace(/\s*\($/, '');
        return {
          ruleId: this.ruleId,
          message: `System command function '${funcName}' detected`,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

/**
 * Detects file system access patterns.
 */
const fileAccessRule: Rule = {
  ruleId: 'file-access',
  name: 'File Access Detection',
  description: 'Detects INTO OUTFILE, LOAD DATA, COPY, pg_read_file, etc.',
  severity: RuleSeverity.CRITICAL,
  check(sql: string): RuleViolation | null {
    const patterns = [
      { pattern: /\bINTO\s+OUTFILE\b/i, message: 'INTO OUTFILE clause detected' },
      { pattern: /\bINTO\s+DUMPFILE\b/i, message: 'INTO DUMPFILE clause detected' },
      { pattern: /\bLOAD\s+DATA\s+INFILE\b/i, message: 'LOAD DATA INFILE detected' },
      { pattern: /\bLOAD_FILE\s*\(/i, message: 'LOAD_FILE function detected' },
      { pattern: /\bpg_read_file\s*\(/i, message: "Dangerous file function 'pg_read_file' detected" },
      { pattern: /\bpg_read_binary_file\s*\(/i, message: 'pg_read_binary_file function detected' },
      { pattern: /\bCOPY\s+\w+\s+(TO|FROM)\b/i, message: 'COPY command detected' },
    ];

    for (const { pattern, message } of patterns) {
      if (pattern.test(sql)) {
        return {
          ruleId: this.ruleId,
          message,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

/**
 * Detects dynamic SQL execution.
 */
const dynamicSqlRule: Rule = {
  ruleId: 'dynamic-sql',
  name: 'Dynamic SQL Detection',
  description: 'Detects EXEC, EXECUTE, PREPARE statements',
  severity: RuleSeverity.CRITICAL,
  check(sql: string): RuleViolation | null {
    const patterns = [
      { pattern: /\bEXEC\s*\(/i, message: 'EXEC statement detected' },
      { pattern: /\bEXECUTE\s+/i, message: 'EXECUTE statement detected' },
      { pattern: /\bPREPARE\s+\w+\s+FROM\b/i, message: 'PREPARE statement detected' },
      { pattern: /\bsp_executesql\b/i, message: 'sp_executesql detected' },
    ];

    for (const { pattern, message } of patterns) {
      if (pattern.test(sql)) {
        return {
          ruleId: this.ruleId,
          message,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

/**
 * Detects privilege escalation attempts.
 */
const privilegeEscalationRule: Rule = {
  ruleId: 'privilege-escalation',
  name: 'Privilege Escalation Detection',
  description: 'Detects CREATE USER, ALTER USER, SET ROLE',
  severity: RuleSeverity.CRITICAL,
  check(sql: string): RuleViolation | null {
    const patterns = [
      { pattern: /\bCREATE\s+USER\b/i, message: 'CREATE USER detected' },
      { pattern: /\bALTER\s+USER\b/i, message: 'ALTER USER detected' },
      { pattern: /\bSET\s+ROLE\b/i, message: 'SET ROLE detected' },
      { pattern: /\bGRANT\b/i, message: 'GRANT statement detected' },
      { pattern: /\bSUPERUSER\b/i, message: 'SUPERUSER privilege detected' },
    ];

    for (const { pattern, message } of patterns) {
      if (pattern.test(sql)) {
        return {
          ruleId: this.ruleId,
          message,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

/**
 * Detects stored procedure calls.
 */
const storedProcedureRule: Rule = {
  ruleId: 'stored-procedure',
  name: 'Stored Procedure Detection',
  description: 'Detects CALL statements',
  severity: RuleSeverity.HIGH,
  check(sql: string): RuleViolation | null {
    if (/\bCALL\s+\w+/i.test(sql)) {
      return {
        ruleId: this.ruleId,
        message: 'CALL statement detected',
        severity: this.severity,
      };
    }
    return null;
  },
};

/**
 * Detects dangerous timing/benchmark functions.
 */
const dangerousFunctionsRule: Rule = {
  ruleId: 'dangerous-functions',
  name: 'Dangerous Functions Detection',
  description: 'Detects SLEEP, BENCHMARK, and similar DoS-prone functions',
  severity: RuleSeverity.MEDIUM,
  check(sql: string): RuleViolation | null {
    const patterns = [
      { pattern: /\bSLEEP\s*\(/i, message: 'SLEEP function detected (timing attack)' },
      { pattern: /\bpg_sleep\s*\(/i, message: 'pg_sleep function detected (timing attack)' },
      { pattern: /\bBENCHMARK\s*\(/i, message: 'BENCHMARK function detected (DoS vector)' },
      { pattern: /\bWAITFOR\s+DELAY\b/i, message: 'WAITFOR DELAY detected (timing attack)' },
    ];

    for (const { pattern, message } of patterns) {
      if (pattern.test(sql)) {
        return {
          ruleId: this.ruleId,
          message,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

/**
 * Detects hex-encoded SQL keywords.
 */
const hexEncodingRule: Rule = {
  ruleId: 'hex-encoding',
  name: 'Hex Encoding Detection',
  description: 'Detects hex-encoded SQL keywords like 0x44524F50 (DROP)',
  severity: RuleSeverity.MEDIUM,
  check(sql: string): RuleViolation | null {
    const hexPattern = /0x([0-9A-Fa-f]{6,})/g;
    const dangerousKeywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'EXEC', 'UNION', 'SELECT'];

    let match;
    while ((match = hexPattern.exec(sql)) !== null) {
      try {
        const hexValue = match[1];
        if (!hexValue) continue;
        // Convert hex to string
        let decoded = '';
        for (let i = 0; i < hexValue.length; i += 2) {
          decoded += String.fromCharCode(parseInt(hexValue.substring(i, i + 2), 16));
        }
        const decodedUpper = decoded.toUpperCase();

        for (const keyword of dangerousKeywords) {
          if (decodedUpper.includes(keyword)) {
            return {
              ruleId: this.ruleId,
              message: `Hex-encoded SQL keyword detected: '${keyword}' in ${match[0]}`,
              severity: this.severity,
            };
          }
        }
      } catch {
        // Invalid hex, skip
      }
    }
    return null;
  },
};

/**
 * Detects CHAR() function abuse.
 */
const charFunctionRule: Rule = {
  ruleId: 'char-function',
  name: 'CHAR Function Detection',
  description: 'Detects CHAR() function constructing SQL keywords',
  severity: RuleSeverity.MEDIUM,
  check(sql: string): RuleViolation | null {
    const dangerousKeywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'EXEC', 'UNION'];

    // Look for CHAR(xx) or CHR(xx) patterns
    const charPattern = /\bCH(?:AR|R)\s*\(\s*(\d+)\s*\)/gi;
    const chars: number[] = [];

    let match;
    while ((match = charPattern.exec(sql)) !== null) {
      const charCode = match[1];
      if (charCode) {
        chars.push(parseInt(charCode, 10));
      }
    }

    if (chars.length >= 4) {
      // Try to construct strings from consecutive chars
      const constructed = chars.map((c) => String.fromCharCode(c)).join('');

      for (const keyword of dangerousKeywords) {
        if (constructed.toUpperCase().includes(keyword)) {
          return {
            ruleId: this.ruleId,
            message: `CHAR()-constructed SQL keyword detected: '${keyword}'`,
            severity: this.severity,
          };
        }
      }
    }

    return null;
  },
};

/**
 * Detects string concatenation building SQL keywords.
 */
const stringConcatRule: Rule = {
  ruleId: 'string-concat',
  name: 'String Concatenation Detection',
  description: "Detects string concatenation building keywords like 'DR' || 'OP'",
  severity: RuleSeverity.MEDIUM,
  check(sql: string): RuleViolation | null {
    const dangerousKeywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'EXEC', 'UNION'];

    // Look for 'xxx' || 'yyy' or CONCAT('xxx', 'yyy') patterns
    const concatPattern = /'([^']+)'\s*\|\|\s*'([^']+)'/g;

    let match;
    while ((match = concatPattern.exec(sql)) !== null) {
      const part1 = match[1];
      const part2 = match[2];
      if (!part1 || !part2) continue;
      const combined = (part1 + part2).toUpperCase();

      for (const keyword of dangerousKeywords) {
        if (combined.includes(keyword)) {
          return {
            ruleId: this.ruleId,
            message: `String concatenation building '${keyword}' detected`,
            severity: this.severity,
          };
        }
      }
    }

    return null;
  },
};

/**
 * Detects Unicode homoglyph attacks.
 */
const unicodeObfuscationRule: Rule = {
  ruleId: 'unicode-obfuscation',
  name: 'Unicode Obfuscation Detection',
  description: 'Detects Cyrillic/Greek characters masquerading as ASCII',
  severity: RuleSeverity.HIGH,
  check(sql: string): RuleViolation | null {
    // Common Cyrillic/Greek homoglyphs that look like ASCII
    const homoglyphs: Record<string, string> = {
      '\u0430': 'a', // Cyrillic а
      '\u0435': 'e', // Cyrillic е
      '\u043E': 'o', // Cyrillic о
      '\u0440': 'p', // Cyrillic р
      '\u0441': 'c', // Cyrillic с
      '\u0445': 'x', // Cyrillic х
      '\u0443': 'y', // Cyrillic у
      '\u0456': 'i', // Cyrillic і
      '\u0391': 'A', // Greek Α
      '\u0392': 'B', // Greek Β
      '\u0395': 'E', // Greek Ε
      '\u0397': 'H', // Greek Η
      '\u0399': 'I', // Greek Ι
      '\u039A': 'K', // Greek Κ
      '\u039C': 'M', // Greek Μ
      '\u039D': 'N', // Greek Ν
      '\u039F': 'O', // Greek Ο
      '\u03A1': 'P', // Greek Ρ
      '\u03A4': 'T', // Greek Τ
      '\u03A7': 'X', // Greek Χ
      '\u03A5': 'Y', // Greek Υ
      '\u0417': 'Z', // Greek Ζ
    };

    for (const char of sql) {
      if (homoglyphs[char]) {
        return {
          ruleId: this.ruleId,
          message: `Unicode homoglyphs detected - possible keyword obfuscation`,
          severity: this.severity,
        };
      }
    }

    return null;
  },
};

/**
 * Detects transaction abuse patterns.
 */
const transactionAbuseRule: Rule = {
  ruleId: 'transaction-abuse',
  name: 'Transaction Abuse Detection',
  description: 'Detects LOCK TABLE and other DoS vectors',
  severity: RuleSeverity.MEDIUM,
  check(sql: string): RuleViolation | null {
    if (/\bLOCK\s+TABLE\b/i.test(sql)) {
      return {
        ruleId: this.ruleId,
        message: 'LOCK TABLE detected (DoS vector)',
        severity: this.severity,
      };
    }
    return null;
  },
};

/**
 * Detects metadata/schema access.
 */
const metadataAccessRule: Rule = {
  ruleId: 'metadata-access',
  name: 'Metadata Access Detection',
  description: 'Detects access to information_schema, pg_catalog, etc.',
  severity: RuleSeverity.LOW,
  check(sql: string): RuleViolation | null {
    const patterns = [
      { pattern: /\binformation_schema\b/i, message: 'Access to information_schema detected' },
      { pattern: /\bpg_catalog\b/i, message: 'Access to pg_catalog detected' },
      { pattern: /\bpg_\w+\b/i, message: 'Access to PostgreSQL system table detected' },
      { pattern: /\bmysql\.\w+\b/i, message: 'Access to MySQL system table detected' },
      { pattern: /\bsys\.\w+\b/i, message: 'Access to sys schema detected' },
    ];

    for (const { pattern, message } of patterns) {
      if (pattern.test(sql)) {
        return {
          ruleId: this.ruleId,
          message,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

/**
 * Detects schema introspection commands.
 */
const schemaCommandRule: Rule = {
  ruleId: 'schema-commands',
  name: 'Schema Command Detection',
  description: 'Detects SHOW TABLES, DESCRIBE, EXPLAIN',
  severity: RuleSeverity.LOW,
  check(sql: string): RuleViolation | null {
    const patterns = [
      { pattern: /\bSHOW\s+TABLES\b/i, message: 'SHOW TABLES detected' },
      { pattern: /\bSHOW\s+DATABASES\b/i, message: 'SHOW DATABASES detected' },
      { pattern: /\bDESCRIBE\s+\w+\b/i, message: 'DESCRIBE command detected' },
      { pattern: /\bDESC\s+\w+\b/i, message: 'DESC command detected' },
    ];

    for (const { pattern, message } of patterns) {
      if (pattern.test(sql)) {
        return {
          ruleId: this.ruleId,
          message,
          severity: this.severity,
        };
      }
    }
    return null;
  },
};

// ============================================================================
// Rule Registry
// ============================================================================

const ALL_RULES: Rule[] = [
  systemCommandRule,
  fileAccessRule,
  dynamicSqlRule,
  privilegeEscalationRule,
  storedProcedureRule,
  dangerousFunctionsRule,
  hexEncodingRule,
  charFunctionRule,
  stringConcatRule,
  unicodeObfuscationRule,
  transactionAbuseRule,
  metadataAccessRule,
  schemaCommandRule,
];

/**
 * Get all registered security rules.
 */
export function getAllRules(): Rule[] {
  return ALL_RULES;
}

/**
 * Run security rules against a SQL query.
 */
export function runSecurityRules(
  sql: string,
  ast: AST | AST[],
  config: SecurityConfig
): ValidationResult {
  for (const rule of ALL_RULES) {
    // Check if this rule should run based on config
    if (!config.shouldRunRule(rule.ruleId, rule.severity)) {
      continue;
    }

    const violation = rule.check(sql, ast);
    if (violation && config.shouldFail(violation.severity)) {
      return ValidationResult.unsafe(violation.message);
    }
  }

  return ValidationResult.safe();
}

