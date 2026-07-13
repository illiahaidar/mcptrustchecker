import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeEnv, isBlockedHost } from '../src/acquire/live.js';
import { hasBase64Blob } from '../src/util/text.js';
import { computeScore } from '../src/scoring/index.js';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { injectionDetector } from '../src/detectors/injection.js';
import { postureDetector } from '../src/detectors/posture.js';
import { buildCtx, makeSurface } from './helpers.js';
import type { Finding } from '../src/types.js';

test('sanitizeEnv strips execution-hijacking variables but keeps benign ones', () => {
  const { clean, dropped } = sanitizeEnv({
    NODE_OPTIONS: '--require /tmp/pwn.js',
    LD_PRELOAD: '/tmp/evil.so',
    DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib',
    PYTHONSTARTUP: '/tmp/x.py',
    BASH_FUNC_x: '() { evil; }',
    API_BASE: 'https://example.com',
  });
  assert.equal(clean.API_BASE, 'https://example.com');
  assert.ok(!('NODE_OPTIONS' in clean));
  assert.ok(!('LD_PRELOAD' in clean));
  assert.ok(!('DYLD_INSERT_LIBRARIES' in clean));
  assert.ok(!('PYTHONSTARTUP' in clean));
  assert.ok(!('BASH_FUNC_x' in clean)); // () value dropped
  assert.ok(dropped.includes('NODE_OPTIONS'));
});

test('isBlockedHost catches loopback/private/link-local (SSRF)', () => {
  for (const h of ['127.0.0.1', 'localhost', '::1', '10.1.2.3', '192.168.0.1', '172.16.0.1', '169.254.169.254']) {
    assert.equal(isBlockedHost(h), true, `${h} should be blocked`);
  }
  for (const h of ['example.com', '8.8.8.8', 'mcp.acme.io']) {
    assert.equal(isBlockedHost(h), false, `${h} should be allowed`);
  }
});

test('hasBase64Blob rejects hex IDs / git SHAs but accepts real base64', () => {
  assert.equal(hasBase64Blob('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'), false); // 32-char hex
  assert.equal(hasBase64Blob('e83c5163316f89bfbde7d9ab23ca2e25604af290'), false); // git SHA
  assert.equal(hasBase64Blob('TWFuIGlzIGRpc3Rpbmd1aXNoZWQgYnkgdGhpcw=='), true); // real base64
});

test('MTC-INJ-ENC-2 does not fire on a benign description with a hex id and the word "run"', () => {
  const surface = makeSurface({
    tools: [{ name: 'report', description: 'Run the report for account a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 and return results.' }],
  });
  const findings = injectionDetector.run(buildCtx(surface));
  assert.ok(!findings.some((f) => f.ruleId === 'MTC-INJ-ENC-2'));
});

test('posture detector tolerates a non-string transport.url without crashing', () => {
  const surface = surfaceFromManifest(
    { tools: [{ name: 't', description: 'x' }], transport: { kind: 'http', url: 8080 } },
    'bad.json',
  );
  assert.doesNotThrow(() => postureDetector.run(buildCtx(surface)));
});

test('a deeply-nested inputSchema does not overflow the stack', async () => {
  let schema: Record<string, unknown> = { type: 'string', description: 'leaf' };
  for (let i = 0; i < 5000; i++) schema = { type: 'object', properties: { a: schema } };
  const surface = makeSurface({ tools: [{ name: 'deep', description: 'x', inputSchema: schema }] });
  const report = await scanSurface(surface);
  assert.ok(report.score.score >= 0); // completed without throwing
});

const crit = (confidence: Finding['confidence']): Finding => ({
  ruleId: 'MTC-X',
  title: 't',
  category: 'injection',
  severity: 'critical',
  confidence,
  description: '',
});

test('any critical caps the grade at D even at low confidence (anti-gaming)', () => {
  assert.equal(computeScore([crit('confirmed')]).grade, 'F');
  assert.equal(computeScore([crit('strong')]).grade, 'D');
  assert.equal(computeScore([crit('heuristic')]).grade, 'D'); // would be B by number alone
  assert.equal(computeScore([crit('speculative')]).grade, 'D'); // would be A by number alone
});

test('an empty/malformed surface is flagged, not graded a clean A silently', async () => {
  const surface = surfaceFromManifest({}, 'empty.json');
  const report = await scanSurface(surface);
  assert.ok(report.findings.some((f) => f.ruleId === 'MTC-META-001'));
});
