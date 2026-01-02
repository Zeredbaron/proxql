import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { validate } from '../index';
import { SecurityConfig, RuleSeverity } from '../security';

const FIXTURES_DIR = path.join(__dirname, '../../../../shared/test-cases');

interface TestCase {
  sql: string;
  options?: {
    mode?: 'read_only' | 'write_safe' | 'custom';
    allowedTables?: string[];
    dialect?: string;
    security?:
      | boolean
      | {
          minimumSeverity?: string;
          failOnLow?: boolean;
          disabledRules?: string[];
          enabledRules?: string[];
        };
  };
  expected: {
    isSafe: boolean;
    reasonContains?: string;
    statementType?: string;
    tablesContain?: string[];
  };
  description?: string;
}

interface TestFixture {
  name: string;
  description?: string;
  tests: TestCase[];
}

function loadTestCases(): Array<{ fixtureName: string; testName: string; test: TestCase }> {
  const cases: Array<{ fixtureName: string; testName: string; test: TestCase }> = [];

  function walk(dir: string) {
    if (!fs.existsSync(dir)) return;

    for (const file of fs.readdirSync(dir)) {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (file.endsWith('.json')) {
        try {
          const data: TestFixture = JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
          for (const test of data.tests) {
            const testName = test.description || test.sql.slice(0, 50);
            cases.push({
              fixtureName: data.name,
              testName,
              test,
            });
          }
        } catch (e) {
          console.error(`Failed to parse ${fullPath}:`, e);
        }
      }
    }
  }

  walk(FIXTURES_DIR);
  return cases;
}

function convertSecurityConfig(
  security:
    | boolean
    | {
        minimumSeverity?: string;
        failOnLow?: boolean;
        disabledRules?: string[];
        enabledRules?: string[];
      }
    | undefined
): boolean | SecurityConfig | undefined {
  if (security === undefined) return undefined;
  if (typeof security === 'boolean') return security;

  return new SecurityConfig({
    minimumSeverity: security.minimumSeverity as RuleSeverity | undefined,
    failOnLow: security.failOnLow,
    disabledRules: security.disabledRules,
    enabledRules: security.enabledRules,
  });
}

const testCases = loadTestCases();

if (testCases.length === 0) {
  describe('Shared Fixtures', () => {
    it.skip('no fixtures found', () => {});
  });
} else {
  // Group tests by fixture name
  const byFixture = new Map<string, Array<{ testName: string; test: TestCase }>>();
  for (const tc of testCases) {
    if (!byFixture.has(tc.fixtureName)) {
      byFixture.set(tc.fixtureName, []);
    }
    byFixture.get(tc.fixtureName)!.push({ testName: tc.testName, test: tc.test });
  }

  for (const [fixtureName, tests] of byFixture) {
    describe(`Shared Fixtures: ${fixtureName}`, () => {
      for (const { testName, test } of tests) {
        it(testName, () => {
          const options = test.options
            ? {
                mode: test.options.mode,
                allowedTables: test.options.allowedTables,
                dialect: test.options.dialect,
                security: convertSecurityConfig(test.options.security),
              }
            : undefined;

          const result = validate(test.sql, options);

          expect(result.isSafe).toBe(test.expected.isSafe);

          if (test.expected.reasonContains && !test.expected.isSafe) {
            expect(result.reason?.toLowerCase()).toContain(
              test.expected.reasonContains.toLowerCase()
            );
          }

          if (test.expected.statementType) {
            expect(result.statementType).toBe(test.expected.statementType);
          }

          if (test.expected.tablesContain) {
            for (const table of test.expected.tablesContain) {
              expect(result.tables.map((t) => t.toLowerCase())).toContain(table.toLowerCase());
            }
          }
        });
      }
    });
  }
}



