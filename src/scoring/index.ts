/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Deterministic scorer. Turns a set of findings into an auditable Trust Score:
 * additive penalties from 100, diminishing returns per rule, per-category caps,
 * then weakest-link hard gates. Same methodology version + same findings ⇒
 * identical score, and every point is reconstructable from `vector`.
 */

import type { Category, Confidence, Finding, Score, ScoreVectorItem } from '../types.js';
import { METHODOLOGY_VERSION } from '../version.js';
import {
  ALL_CATEGORIES,
  bandForScore,
  CATEGORY_CAP,
  CONFIDENCE_MULT,
  DIMINISHING,
  isCapabilityRule,
  SEVERITY_WEIGHT,
  stricterGrade,
} from './model.js';

const CONFIDENCE_ORDER: Record<Confidence, number> = { confirmed: 0, strong: 1, heuristic: 2, speculative: 3 };
const SEVERITY_ORDER: Record<Finding['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Compute the Trust Score for a set of findings (capability rules excluded). */
export function computeScore(findings: Finding[]): Score {
  // The grade reflects TRUST only: capability/blast-radius findings raise the
  // capability level (computed elsewhere) but never lower the grade.
  const threat = findings.filter((f) => !isCapabilityRule(f.ruleId));

  // Deterministic order: strongest confidence, then highest severity first, so
  // the full-weight slot in each rule goes to the most-certain finding.
  const scored = threat
    .filter((f) => f.severity !== 'info')
    .slice()
    .sort((a, b) => {
      if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
      // The full-weight (rank-0) slot must go to the HIGHEST-penalty finding, so
      // that adding a lower-penalty finding can never raise the score (monotonicity).
      const pa = SEVERITY_WEIGHT[a.severity] * CONFIDENCE_MULT[a.confidence];
      const pb = SEVERITY_WEIGHT[b.severity] * CONFIDENCE_MULT[b.confidence];
      if (pa !== pb) return pb - pa;
      if (CONFIDENCE_ORDER[a.confidence] !== CONFIDENCE_ORDER[b.confidence])
        return CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence];
      return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    });

  const rankByRule = new Map<string, number>();
  const vector: ScoreVectorItem[] = [];
  const categoryRaw: Record<Category, number> = Object.fromEntries(ALL_CATEGORIES.map((c) => [c, 0])) as Record<
    Category,
    number
  >;

  for (const f of scored) {
    const rank = rankByRule.get(f.ruleId) ?? 0;
    rankByRule.set(f.ruleId, rank + 1);
    const rawWeight = SEVERITY_WEIGHT[f.severity];
    const confidenceMult = CONFIDENCE_MULT[f.confidence];
    const diminishingFactor = DIMINISHING[Math.min(rank, DIMINISHING.length - 1)]!;
    const appliedPenalty = round2(rawWeight * confidenceMult * diminishingFactor);
    categoryRaw[f.category] += appliedPenalty;
    vector.push({
      ruleId: f.ruleId,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      rawWeight,
      confidenceMult,
      diminishingFactor,
      appliedPenalty,
    });
  }

  const categorySubtotals: Record<Category, number> = Object.fromEntries(
    ALL_CATEGORIES.map((c) => [c, round2(Math.min(CATEGORY_CAP[c], categoryRaw[c]))]),
  ) as Record<Category, number>;

  const totalPenalty = ALL_CATEGORIES.reduce((sum, c) => sum + categorySubtotals[c], 0);
  const score = Math.max(0, Math.min(100, Math.round(100 - totalPenalty)));
  const band = bandForScore(score);

  // Hard gates. Most gates fire only on `confirmed` findings so a guess can't
  // force a cap — but ANY critical (regardless of confidence) floors the grade
  // at D, so a critical-severity issue can never be graded A/B.
  const confirmed = threat.filter((f) => f.confidence === 'confirmed');
  const confirmedCritical = confirmed.filter((f) => f.severity === 'critical').length;
  const confirmedHigh = confirmed.filter((f) => f.severity === 'high').length;
  const anyCritical = threat.some((f) => f.severity === 'critical');

  const gatesFired: string[] = [];
  let gateCap: Score['gateCap'];
  const applyCap = (cap: NonNullable<Score['gateCap']>, reason: string): void => {
    gateCap = gateCap ? stricterGrade(gateCap, cap) : cap;
    gatesFired.push(reason);
  };

  if (confirmedCritical > 0)
    applyCap('F', `${confirmedCritical} confirmed critical finding(s) → grade capped at F`);
  else if (anyCritical) applyCap('D', `a critical finding is present → grade capped at D`);
  if (confirmedHigh >= 2) applyCap('D', `${confirmedHigh} confirmed high findings → grade capped at D`);
  else if (confirmedHigh === 1) applyCap('C', `1 confirmed high finding → grade capped at C`);

  const grade = gateCap ? stricterGrade(band, gateCap) : band;

  return {
    score,
    grade,
    band,
    gateCap,
    categorySubtotals,
    vector,
    gatesFired,
    methodologyVersion: METHODOLOGY_VERSION,
  };
}
