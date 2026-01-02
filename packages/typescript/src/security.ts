/**
 * Severity levels for security rules.
 */
export enum RuleSeverity {
  /** Informational findings (e.g., metadata access) */
  LOW = 'LOW',
  /** Suspicious patterns that may indicate attacks */
  MEDIUM = 'MEDIUM',
  /** Likely malicious patterns */
  HIGH = 'HIGH',
  /** Definitely malicious, immediate threat */
  CRITICAL = 'CRITICAL',
}

/**
 * Numeric values for severity comparison.
 */
const SEVERITY_ORDER: Record<RuleSeverity, number> = {
  [RuleSeverity.LOW]: 1,
  [RuleSeverity.MEDIUM]: 2,
  [RuleSeverity.HIGH]: 3,
  [RuleSeverity.CRITICAL]: 4,
};

/**
 * Compare two severity levels.
 * @returns negative if a < b, positive if a > b, 0 if equal
 */
export function compareSeverity(a: RuleSeverity, b: RuleSeverity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

/**
 * Options for SecurityConfig.
 */
export interface SecurityConfigOptions {
  /** Enable/disable all security rules (default: true) */
  enabled?: boolean;
  /** Minimum severity to check (default: HIGH) */
  minimumSeverity?: RuleSeverity | keyof typeof RuleSeverity;
  /** Rule IDs to skip */
  disabledRules?: Set<string> | string[];
  /** If set, ONLY run these rules (whitelist mode) */
  enabledRules?: Set<string> | string[] | null;
  /** Whether LOW severity findings should block queries (default: false) */
  failOnLow?: boolean;
}

/**
 * Configuration for security rule behavior.
 */
export class SecurityConfig {
  /** Whether security checks are enabled */
  readonly enabled: boolean;

  /** Minimum severity level to check */
  readonly minimumSeverity: RuleSeverity;

  /** Rule IDs that are disabled */
  readonly disabledRules: Set<string>;

  /** If set, only these rules run (whitelist mode) */
  readonly enabledRules: Set<string> | null;

  /** Whether LOW severity should block queries */
  readonly failOnLow: boolean;

  constructor(options: SecurityConfigOptions = {}) {
    this.enabled = options.enabled ?? true;

    // Handle string severity
    if (typeof options.minimumSeverity === 'string') {
      this.minimumSeverity = RuleSeverity[options.minimumSeverity as keyof typeof RuleSeverity];
    } else {
      this.minimumSeverity = options.minimumSeverity ?? RuleSeverity.HIGH;
    }

    // Handle array or Set for disabledRules
    if (Array.isArray(options.disabledRules)) {
      this.disabledRules = new Set(options.disabledRules);
    } else {
      this.disabledRules = options.disabledRules ?? new Set();
    }

    // Handle array or Set for enabledRules
    if (Array.isArray(options.enabledRules)) {
      this.enabledRules = new Set(options.enabledRules);
    } else if (options.enabledRules instanceof Set) {
      this.enabledRules = options.enabledRules;
    } else {
      this.enabledRules = null;
    }

    this.failOnLow = options.failOnLow ?? false;
  }

  /**
   * Check if a rule should run based on this configuration.
   */
  shouldRunRule(ruleId: string, severity: RuleSeverity): boolean {
    if (!this.enabled) return false;

    // Check if rule is disabled
    if (this.disabledRules.has(ruleId)) return false;

    // Check whitelist mode
    if (this.enabledRules !== null && !this.enabledRules.has(ruleId)) {
      return false;
    }

    // Check severity threshold
    if (compareSeverity(severity, this.minimumSeverity) < 0) {
      return false;
    }

    return true;
  }

  /**
   * Check if a finding at this severity should fail validation.
   */
  shouldFail(severity: RuleSeverity): boolean {
    if (severity === RuleSeverity.LOW && !this.failOnLow) {
      return false;
    }
    return true;
  }
}



