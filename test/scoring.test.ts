import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeScore } from '../src/scoring/index.js';
import type { Category, Confidence, Finding, Severity } from '../src/types.js';

let seq = 0;
function f(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: over.ruleId ?? `MTC-TEST-${seq++}`,
    title: 't',
    category: (over.category as Category) ?? 'injection',
    severity: (over.severity as Severity) ?? 'high',
    confidence: (over.confidence as Confidence) ?? 'strong',
    description: '',
    ...over,
  };
}

test('clean surface scores 100 / A', () => {
  const s = computeScore([]);
  assert.equal(s.score, 100);
  assert.equal(s.grade, 'A');
});

test('one confirmed critical caps the grade at F via a hard gate', () => {
  const s = computeScore([f({ ruleId: 'R', severity: 'critical', confidence: 'confirmed' })]);
  assert.equal(s.score, 55); // 100 - 45
  assert.equal(s.band, 'F');
  assert.equal(s.gateCap, 'F');
  assert.equal(s.grade, 'F');
  assert.ok(s.gatesFired.length >= 1);
});

test('confidence multiplier reduces a heuristic penalty', () => {
  const strong = computeScore([f({ ruleId: 'A', severity: 'high', confidence: 'strong' })]).score;
  const heuristic = computeScore([f({ ruleId: 'A', severity: 'high', confidence: 'heuristic' })]).score;
  assert.equal(strong, 85); // 100 - 22*0.7 = 84.6 -> 85
  assert.equal(heuristic, 91); // 100 - 22*0.4 = 91.2 -> 91
  assert.ok(heuristic > strong);
});

test('diminishing returns apply within a single rule', () => {
  const one = computeScore([f({ ruleId: 'DUP', severity: 'high', confidence: 'strong' })]).score;
  const two = computeScore([
    f({ ruleId: 'DUP', severity: 'high', confidence: 'strong' }),
    f({ ruleId: 'DUP', severity: 'high', confidence: 'strong' }),
  ]).score;
  // second finding contributes only half → total 15.4 + 7.7 = 23.1
  assert.equal(one, 85);
  assert.equal(two, 77);
});

test('category cap bounds the damage from one category', () => {
  const findings = [
    f({ ruleId: 'C', severity: 'critical', confidence: 'confirmed', category: 'injection' }),
    f({ ruleId: 'C', severity: 'critical', confidence: 'confirmed', category: 'injection' }),
    f({ ruleId: 'C', severity: 'critical', confidence: 'confirmed', category: 'injection' }),
  ];
  const s = computeScore(findings);
  // 45 + 22.5 + 11.25 = 78.75, capped at injection cap 50 → score 50
  assert.equal(s.categorySubtotals.injection, 50);
  assert.equal(s.score, 50);
});

test('two confirmed highs cap the grade at D', () => {
  const s = computeScore([
    f({ ruleId: 'H1', severity: 'high', confidence: 'confirmed' }),
    f({ ruleId: 'H2', severity: 'high', confidence: 'confirmed' }),
  ]);
  assert.equal(s.gateCap, 'D');
});

test('a heuristic high does NOT fire a gate (only confirmed findings gate)', () => {
  const s = computeScore([f({ ruleId: 'H', severity: 'high', confidence: 'heuristic' })]);
  assert.equal(s.gateCap, undefined);
});

test('scoring is deterministic and order-independent', () => {
  const a = [f({ ruleId: 'X', severity: 'medium' }), f({ ruleId: 'Y', severity: 'low' })];
  const b = [...a].reverse();
  assert.equal(computeScore(a).score, computeScore(b).score);
  assert.deepEqual(computeScore(a).categorySubtotals, computeScore(b).categorySubtotals);
});

test('info findings are recorded but never scored', () => {
  const s = computeScore([f({ ruleId: 'I', severity: 'info', confidence: 'confirmed' })]);
  assert.equal(s.score, 100);
  assert.equal(s.vector.length, 0);
});

// ---------------------------------------------------------------------------
// Client-adoption-risk terms: the score EVOLVES the threat score with three
// subtract-only, itemised terms. threatScore is preserved for audit.
// ---------------------------------------------------------------------------

const clientLine = (s: ReturnType<typeof computeScore>, term: string) =>
  s.vector.find((v) => v.kind === 'client' && v.term === term);

test('no client context ⇒ client score equals the threat score (pure threat call)', () => {
  const s = computeScore([f({ ruleId: 'A', severity: 'high', confidence: 'strong' })]);
  assert.equal(s.score, 85);
  assert.equal(s.threatScore, 85);
  assert.ok(!s.vector.some((v) => v.kind === 'client'));
});

test('CAPABILITY_EXPOSURE subtracts the right points per level', () => {
  const base = { coverageLevel: 'live', verification: 'vendor' } as const; // both 0
  const minimal = computeScore([], { ...base, capabilityLevel: 'minimal' });
  const moderate = computeScore([], { ...base, capabilityLevel: 'moderate' });
  const high = computeScore([], { ...base, capabilityLevel: 'high' });
  const critical = computeScore([], { ...base, capabilityLevel: 'critical' });
  assert.equal(minimal.score, 100);
  assert.equal(moderate.score, 97); // -3
  assert.equal(high.score, 94); // -6
  assert.equal(critical.score, 90); // -10
  assert.equal(clientLine(high, 'capability-exposure')!.appliedPenalty, 6);
  // threatScore is preserved untouched by the client terms.
  assert.equal(critical.threatScore, 100);
});

test('VERIFICATION_DISCOUNT: none < repo < source = vendor, and unknown is SKIPPED', () => {
  const base = { capabilityLevel: 'minimal', coverageLevel: 'live' } as const; // both 0
  const none = computeScore([], { ...base, verification: 'none' });
  const repo = computeScore([], { ...base, verification: 'repo' });
  const source = computeScore([], { ...base, verification: 'source' });
  const vendor = computeScore([], { ...base, verification: 'vendor' });
  const unknown = computeScore([], { ...base, verification: 'unknown' });
  assert.equal(none.score, 95); // -5, source cannot even be located
  assert.equal(repo.score, 99); // -1, public repo the client can read
  assert.equal(source.score, 100); // -0, provenance IS the reward
  assert.equal(vendor.score, 100); // -0, vendor authority
  assert.equal(unknown.score, 100); // term skipped
  // 'unknown' emits NO verification line at all (honest omission, not a 0).
  assert.ok(!clientLine(unknown, 'verification-discount'));
  assert.equal(clientLine(none, 'verification-discount')!.appliedPenalty, 5);
  assert.equal(clientLine(repo, 'verification-discount')!.appliedPenalty, 1);
});

test('COVERAGE_HONESTY subtracts the right points per depth', () => {
  const base = { capabilityLevel: 'minimal', verification: 'vendor' } as const; // both 0
  assert.equal(computeScore([], { ...base, coverageLevel: 'live' }).score, 100);
  assert.equal(computeScore([], { ...base, coverageLevel: 'source' }).score, 100);
  assert.equal(computeScore([], { ...base, coverageLevel: 'manifest' }).score, 96); // -4
  assert.equal(computeScore([], { ...base, coverageLevel: 'metadata' }).score, 92); // -8
  assert.equal(computeScore([], { ...base, coverageLevel: 'empty' }).score, 90); // -10
});

test('a threat-clean HIGH-cap UNVERIFIED package scores high-80s, not 100', () => {
  // threat-clean, high blast radius, anonymous publish, source read online.
  const s = computeScore([], { capabilityLevel: 'high', coverageLevel: 'source', verification: 'none' });
  assert.equal(s.threatScore, 100);
  assert.equal(s.score, 89); // 100 - 6 (high) - 5 (none) - 0 (source)
  assert.equal(s.grade, 'B');
});

test('a vendor + minimal + clean package stays ~100 / A', () => {
  const s = computeScore([], { capabilityLevel: 'minimal', coverageLevel: 'source', verification: 'vendor' });
  assert.equal(s.score, 100);
  assert.equal(s.grade, 'A');
});

test('client terms never raise the score above the threat score, and clamp at 0', () => {
  const crit = computeScore([f({ ruleId: 'C', severity: 'critical', confidence: 'confirmed' })], {
    capabilityLevel: 'critical',
    coverageLevel: 'empty',
    verification: 'none',
  });
  // threat 55, minus E_cap 10 + E_ver 5 + E_cov 10 = 25 → 30, F-gate still holds.
  assert.equal(crit.threatScore, 55);
  assert.equal(crit.score, 30);
  assert.ok(crit.score <= crit.threatScore);
  assert.equal(crit.grade, 'F'); // confirmed-critical F-gate is never softened
});

test('the F-gate is never softened by the client terms (weakest-link held)', () => {
  const s = computeScore([f({ ruleId: 'C', severity: 'critical', confidence: 'confirmed' })], {
    capabilityLevel: 'minimal',
    coverageLevel: 'live',
    verification: 'vendor',
  });
  assert.equal(s.gateCap, 'F');
  assert.equal(s.grade, 'F');
});
