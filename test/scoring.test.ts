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
