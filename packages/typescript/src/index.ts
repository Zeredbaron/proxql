/**
 * ProxQL - The Database Firewall for AI Agents
 *
 * A SQL validation library that blocks destructive queries from LLM-generated SQL.
 *
 * @example
 * ```typescript
 * import proxql from 'proxql';
 *
 * // Simple validation (read_only mode by default)
 * proxql.validate("SELECT * FROM users").isSafe  // true
 * proxql.validate("DROP TABLE users").isSafe     // false
 *
 * // Quick boolean check
 * proxql.isSafe("SELECT * FROM users")  // true
 *
 * // With custom configuration
 * const { Validator } = proxql;
 * const v = new Validator({ mode: "read_only", allowedTables: ["products"] });
 * v.validate("SELECT * FROM products").isSafe  // true
 * v.validate("SELECT * FROM users").isSafe     // false
 * ```
 *
 * @packageDocumentation
 */

export { Validator } from './validator';
export type { ValidatorOptions, Mode } from './validator';
export { ValidationResult } from './result';
export { SecurityConfig, RuleSeverity } from './security';
export type { SecurityConfigOptions } from './security';
export { CostEstimator, CostLevel, isCostAcceptable } from './cost';
export type { CostEstimate } from './cost';
export { LimitEnforcer, isLimitOk } from './limits';
export type { LimitCheckResult, LimitEnforcerOptions } from './limits';

import { Validator, type ValidatorOptions } from './validator';
import type { ValidationResult } from './result';
import type { SecurityConfig, SecurityConfigOptions } from './security';

/**
 * Options for the validate() and isSafe() functions.
 */
export interface ValidateOptions {
  /** Validation mode - "read_only", "write_safe", or "custom" */
  mode?: 'read_only' | 'write_safe' | 'custom';
  /** Optional list of table names that can be accessed */
  allowedTables?: string[];
  /** SQL dialect for parsing ('postgres', 'mysql', 'snowflake', etc.) */
  dialect?: string;
  /**
   * Security rule configuration:
   * - true (default): Enable default rules (HIGH+ severity)
   * - false: Disable security rules
   * - SecurityConfig or SecurityConfigOptions: Custom security configuration
   */
  security?: boolean | SecurityConfig | SecurityConfigOptions;
}

// Default validator instance for simple API
const defaultValidator = new Validator({ mode: 'read_only' });

/**
 * Validate a SQL query.
 *
 * This is the simplest way to use ProxQL. For repeated validations with the
 * same configuration, create a Validator instance for better performance.
 *
 * @param sql - The SQL query string to validate
 * @param options - Validation options
 * @returns ValidationResult with isSafe=true if query passes,
 *          or isSafe=false with a reason explaining why it was blocked
 *
 * @example
 * ```typescript
 * import { validate } from 'proxql';
 *
 * // Basic validation (blocks all non-SELECT)
 * validate("SELECT * FROM users").isSafe  // true
 * validate("DROP TABLE users").isSafe     // false
 *
 * // Allow writes
 * validate("INSERT INTO logs VALUES (1)", { mode: "write_safe" }).isSafe  // true
 *
 * // Restrict to specific tables
 * validate("SELECT * FROM users", {
 *   allowedTables: ["products", "categories"]
 * }).isSafe  // false
 * ```
 */
export function validate(sql: string, options?: ValidateOptions): ValidationResult {
  // Use default validator for simple read_only case (optimization)
  // Only use default if no options, or options are all defaults
  const isDefault =
    !options ||
    ((options.mode === 'read_only' || options.mode === undefined) &&
      !options.allowedTables &&
      !options.dialect &&
      (options.security === true || options.security === undefined));

  if (isDefault) {
    return defaultValidator.validate(sql);
  }

  // Create a one-off validator for custom configuration
  const validatorOptions: ValidatorOptions = {
    mode: options?.mode ?? 'read_only',
    allowedTables: options?.allowedTables,
    dialect: options?.dialect,
    securityConfig: options?.security,
  };

  const validator = new Validator(validatorOptions);
  return validator.validate(sql);
}

/**
 * Check if a SQL query is safe (convenience wrapper).
 *
 * This is a shorthand for `validate(sql).isSafe`. Use this when you only
 * need a boolean result and don't need the detailed ValidationResult.
 *
 * @param sql - The SQL query string to validate
 * @param options - Validation options
 * @returns true if the query passes all validation checks, false otherwise
 *
 * @example
 * ```typescript
 * import { isSafe } from 'proxql';
 *
 * if (isSafe(userQuery)) {
 *   executeQuery(userQuery);
 * } else {
 *   throw new Error("Query blocked");
 * }
 * ```
 */
export function isSafe(sql: string, options?: ValidateOptions): boolean {
  return validate(sql, options).isSafe;
}

// Default export for convenience
export default {
  validate,
  isSafe,
  Validator,
};

