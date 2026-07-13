/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Cross-version test runner. Node's built-in test runner only learned to expand
 * glob patterns (`--test 'test/**\/*.test.ts'`) in Node 21, so on Node 20 the
 * glob is treated as a literal path and no tests run. This finds the test files
 * ourselves (pure Node, cross-platform) and passes them explicitly, which works
 * on every supported Node (>=20).
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function findTests(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...findTests(full));
    else if (entry.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

// Sort for deterministic, stable ordering across machines.
const files = findTests('test').sort();
if (files.length === 0) {
  console.error('run-tests: no *.test.ts files found under test/');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--import', 'tsx', '--test', ...files], {
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
