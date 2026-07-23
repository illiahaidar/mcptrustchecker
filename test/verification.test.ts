import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyPublisher } from '../src/acquire/publisher.js';
import { scanSurface } from '../src/engine.js';
import { computeCoverage } from '../src/scoring/coverage.js';
import { makeSurface } from './helpers.js';
import type { ServerSurface } from '../src/types.js';

// The verification classifier is the SAME engine signal used by the CLI, the
// registry and the hosted API — ported from the API so every mode agrees. These
// tests exercise it with static registry documents (no network).

const npmDoc = (over: Record<string, unknown> = {}) => ({
  'dist-tags': { latest: '1.0.0' },
  versions: { '1.0.0': { dist: {} } },
  ...over,
});

test('npm: build provenance (SLSA attestation) ⇒ source verified', () => {
  const doc = npmDoc({ versions: { '1.0.0': { dist: { attestations: { provenance: {} } } } } });
  const id = classifyPublisher('npm', 'some-tool', doc, 'https://github.com/someone/some-tool');
  assert.equal(id.verification, 'source');
});

test('npm: a vendor-owned scope is an authorization fact ⇒ vendor verified', () => {
  const id = classifyPublisher('npm', '@azure/mcp-server', npmDoc(), null);
  assert.equal(id.verification, 'vendor');
  assert.equal(id.vendor, 'Microsoft Azure');
});

test('npm: provenance to a known vendor org ⇒ vendor verified', () => {
  const doc = npmDoc({ versions: { '1.0.0': { dist: { attestations: { provenance: {} } } } } });
  const id = classifyPublisher('npm', 'server-everything', doc, 'https://github.com/modelcontextprotocol/servers');
  assert.equal(id.verification, 'vendor');
  assert.equal(id.vendor, 'Model Context Protocol');
});

test('npm: no provenance, no vendor scope, but a public repo ⇒ repo (inspectable)', () => {
  // Unverified, yet the source is public — the ecosystem norm, a light discount.
  const id = classifyPublisher('npm', 'random-thing', npmDoc(), 'https://github.com/nobody/random-thing');
  assert.equal(id.verification, 'repo');
});

test('npm: no provenance and NO repository ⇒ none (source cannot be located)', () => {
  const id = classifyPublisher('npm', 'random-thing', npmDoc(), null);
  assert.equal(id.verification, 'none');
});

test('a scope name inside the package name proves nothing without the scope owning it', () => {
  // "safari-mcp" is not Apple's; an unscoped brandish name stays unverified —
  // but its source is public, so it lands at `repo`, not vendor.
  const id = classifyPublisher('npm', 'safari-mcp', npmDoc(), 'https://github.com/randomdev/safari-mcp');
  assert.equal(id.verification, 'repo');
  assert.equal(id.vendor, null);
});

test('pypi: PEP 740 attestation on a file ⇒ source verified', () => {
  const doc = { info: {}, urls: [{ attestations: [{}] }] };
  const id = classifyPublisher('pypi', 'mcp-thing', doc, 'https://github.com/someone/mcp-thing');
  assert.equal(id.verification, 'source');
});

// --- Engine wiring: offline vs online is input-dependent, not a code fork. ---

test('OFFLINE scan: verification is unknown, the term is skipped, a caveat is recorded', async () => {
  // A metadata-only package surface with NO verification set (offline).
  const surface: ServerSurface = makeSurface({
    source: { kind: 'package', origin: 'left-pad' },
    packageMeta: { registry: 'npm', name: 'left-pad' },
  });
  const report = await scanSurface(surface);
  // No verification line in the vector...
  assert.ok(!report.score.vector.some((v) => v.kind === 'client' && v.term === 'verification-discount'));
  // ...and an honest caveat says why.
  assert.ok(report.coverage.caveats.some((c) => /Publisher verification was not checked/.test(c)));
});

test('ONLINE-style scan: a verification set on packageMeta IS applied to the score', async () => {
  // Simulate what an --online fetch stamps on the surface (verification: none).
  const surface: ServerSurface = makeSurface({
    source: { kind: 'package', origin: 'random-thing' },
    packageMeta: { registry: 'npm', name: 'random-thing', verification: 'none' },
  });
  const report = await scanSurface(surface);
  const verLine = report.score.vector.find((v) => v.kind === 'client' && v.term === 'verification-discount');
  assert.ok(verLine, 'online scan must apply the verification term');
  assert.equal(verLine!.appliedPenalty, 5); // none ⇒ -5
  // The no-provenance caveat must NOT appear when verification WAS checked.
  assert.ok(!report.coverage.caveats.some((c) => /Publisher verification was not checked/.test(c)));
});

test('computeCoverage adds the caveat only for an unchecked package target', () => {
  const pkg = makeSurface({ source: { kind: 'package', origin: 'p' }, packageMeta: { registry: 'npm', name: 'p' } });
  assert.ok(computeCoverage(pkg, 'unknown').caveats.some((c) => /Publisher verification was not checked/.test(c)));
  assert.ok(!computeCoverage(pkg, 'none').caveats.some((c) => /Publisher verification was not checked/.test(c)));
  // A live server with no package identity should not nag about provenance.
  const live = makeSurface({ source: { kind: 'stdio', origin: 'x' }, tools: [{ name: 't' }] });
  assert.ok(!computeCoverage(live, 'unknown').caveats.some((c) => /Publisher verification was not checked/.test(c)));
});

// --- repoUrl extraction robustness (the `repo` tier depends on it) ----------

test('normalizeRepoUrl canonicalizes git+/ssh/.git shapes', async () => {
  const { normalizeRepoUrl } = await import('../src/acquire/npm.js');
  assert.equal(normalizeRepoUrl('git+https://github.com/o/r.git'), 'https://github.com/o/r');
  assert.equal(normalizeRepoUrl('git@github.com:o/r.git'), 'https://github.com/o/r');
  assert.equal(normalizeRepoUrl({ url: 'git://github.com/o/r.git' }), 'https://github.com/o/r');
  assert.equal(normalizeRepoUrl('not a url'), null);
  assert.equal(normalizeRepoUrl(null), null);
});

test('pickNpmRepoUrl falls back to homepage/bugs on a code forge (claude-code case)', async () => {
  const { pickNpmRepoUrl } = await import('../src/acquire/npm.js');
  // Explicit repository wins.
  assert.equal(pickNpmRepoUrl({}, { repository: { url: 'git+https://github.com/o/r.git' } }), 'https://github.com/o/r');
  // No repository, but homepage points at GitHub — the @anthropic-ai/claude-code shape.
  assert.equal(pickNpmRepoUrl({}, { homepage: 'https://github.com/anthropics/claude-code', bugs: { url: 'https://github.com/anthropics/claude-code/issues' } }),
    'https://github.com/anthropics/claude-code');
  // bugs.url with an /issues suffix is trimmed to the repo root.
  assert.equal(pickNpmRepoUrl({}, { bugs: { url: 'https://github.com/o/r/issues' } }), 'https://github.com/o/r');
  // A non-forge docs homepage is NOT accepted as source.
  assert.equal(pickNpmRepoUrl({}, { homepage: 'https://example.com/docs' }), null);
  // Nothing locatable → null (MTC-SUP-011 legitimately fires).
  assert.equal(pickNpmRepoUrl({}, {}), null);
});
