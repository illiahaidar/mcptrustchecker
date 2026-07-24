import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeEnv, isBlockedHost, isBlockedHostResolved } from '../src/acquire/live.js';
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

test('isBlockedHost also covers CGNAT, multicast and reserved space', () => {
  // A scanner reachable from the internet must not be usable to probe a
  // carrier's CGNAT range or to spray multicast/broadcast traffic.
  for (const h of ['100.64.0.1', '100.127.255.254', '224.0.0.1', '239.1.1.1', '240.0.0.1', '255.255.255.255']) {
    assert.equal(isBlockedHost(h), true, `${h} should be blocked`);
  }
  // 100.63.x and 100.128.x sit OUTSIDE 100.64/10 and stay routable.
  for (const h of ['100.63.255.255', '100.128.0.1']) {
    assert.equal(isBlockedHost(h), false, `${h} should be allowed`);
  }
});

test('isBlockedHostResolved catches DNS rebinding that the string check cannot', async () => {
  // Resolution is injected: asserting against a live third-party domain would
  // make this suite fail offline and on any resolver with DNS-rebinding
  // protection — which exists precisely to strip the answer under test.
  const answers = (...ips: string[]) => async () => ips.map((address) => ({ address }));

  // The whole point: a perfectly PUBLIC name whose A record points at loopback.
  // The string guard says "fine" — only resolution reveals it.
  assert.equal(isBlockedHost('rebind.example.com'), false, 'string check cannot see the A record');
  assert.equal(await isBlockedHostResolved('rebind.example.com', answers('127.0.0.1')), true,
    'resolved check must block it');

  // A name is only as safe as its WORST answer.
  assert.equal(await isBlockedHostResolved('multi.example.com', answers('93.184.216.34', '169.254.169.254')), true);
  assert.equal(await isBlockedHostResolved('good.example.com', answers('93.184.216.34')), false);

  // Literals short-circuit without ever calling the resolver.
  let called = false;
  const spy = async () => { called = true; return []; };
  assert.equal(await isBlockedHostResolved('127.0.0.1', spy), true);
  assert.equal(called, false, 'an IP literal must not trigger a lookup');

  // An unresolvable name is NOT treated as blocked: the connection fails on its
  // own, and failing closed here would break split-horizon DNS.
  const fails = async () => { throw new Error('ENOTFOUND'); };
  assert.equal(await isBlockedHostResolved('gone.example.com', fails), false);
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
