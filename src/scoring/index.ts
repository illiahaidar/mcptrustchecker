/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Deterministic scorer. Turns a set of findings into an auditable Trust Score:
 * additive penalties from 100, diminishing returns per rule, per-category caps,
 * then weakest-link hard gates. Same methodology version + same findings ⇒
 * identical score, and every point is reconstructable from `vector`.
 */

import type {
  CapabilityLevel,
  Category,
  Confidence,
  CoverageLevel,
  Finding,
  Score,
  ScoreVectorItem,
  Verification,
} from '../types.js';
import { METHODOLOGY_VERSION } from '../version.js';
import {
  ALL_CATEGORIES,
  bandForScore,
  CAPABILITY_EXPOSURE,
  CATEGORY_CAP,
  CONFIDENCE_MULT,
  COVERAGE_HONESTY,
  DIMINISHING,
  isCapabilityRule,
  SEVERITY_WEIGHT,
  stricterGrade,
  VERIFICATION_DISCOUNT,
} from './model.js';

/**
 * The three inputs that turn the pure THREAT score into the CLIENT-ADOPTION-RISK
 * score. Supplied by the engine, which knows all three once the surface is
 * analysed. When omitted (a direct threat-only call), no client term is applied
 * and the client score equals the threat score.
 */
export interface ClientScoringContext {
  /** Blast radius if the model driving the server were manipulated. */
  capabilityLevel: CapabilityLevel;
  /** How much of the target the scan could actually inspect. */
  coverageLevel: CoverageLevel;
  /** How verifiable the source is; `unknown` (offline) skips the term. */
  verification: Verification;
}

const CONFIDENCE_ORDER: Record<Confidence, number> = { confirmed: 0, strong: 1, heuristic: 2, speculative: 3 };
const SEVERITY_ORDER: Record<Finding['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Plain-language label for each verification tier, from the CLIENT's point of
 * view ("what can I actually check about this code before I run it?"). Kept here
 * so the score vector — the public "why this grade" breakdown — reads for a human
 * rather than surfacing the raw enum token.
 */
const VERIFICATION_LABEL: Record<Exclude<Verification, 'unknown'>, string> = {
  vendor: 'publisher verification (official vendor) — published under a known vendor’s authority',
  source: 'publisher verification (provenance) — cryptographic build provenance ties the artifact to its source',
  repo: 'publisher verification (public source) — no provenance, but the source is public and inspectable',
  none: 'publisher verification (unlocatable) — no provenance and no public repository to inspect',
};

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * Compute the Trust Score for a set of findings (capability rules excluded).
 *
 * With a {@link ClientScoringContext}, three subtract-only client-adoption-risk
 * terms EVOLVE the threat score into the client score — each an itemised line in
 * `vector`, the threat score preserved as `threatScore`. The threat machinery
 * (severity × confidence × diminishing, category caps, the confirmed-critical
 * F-gate) is byte-identical whether or not the context is supplied.
 */
export function computeScore(findings: Finding[], client?: ClientScoringContext): Score {
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
      kind: 'threat',
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

  // The pure THREAT score — unchanged from v1.5.0. Preserved on the report as a
  // sub-field so every point of the client score below is reconstructable.
  const threatScore = Math.max(0, Math.min(100, Math.round(100 - totalPenalty)));

  // CLIENT-ADOPTION-RISK terms: subtract-only, itemised, no black box. Applied
  // only when the engine supplies the context (offline direct calls stay pure
  // threat). The client score can never rise above the threat score.
  let score = threatScore;
  if (client) {
    const eCap = CAPABILITY_EXPOSURE[client.capabilityLevel];
    vector.push({
      kind: 'client',
      term: 'capability-exposure',
      level: client.capabilityLevel,
      label: `capability blast radius (${client.capabilityLevel}) — client exposure if the model is manipulated`,
      appliedPenalty: eCap,
    });

    let eVer = 0;
    if (client.verification !== 'unknown') {
      // `unknown` = an offline scan could not check provenance, so the term is
      // skipped entirely (a coverage caveat records the omission) — never
      // penalised or credited on a guess.
      eVer = VERIFICATION_DISCOUNT[client.verification];
      vector.push({
        kind: 'client',
        term: 'verification-discount',
        level: client.verification,
        label: VERIFICATION_LABEL[client.verification],
        appliedPenalty: eVer,
      });
    }

    const eCov = COVERAGE_HONESTY[client.coverageLevel];
    vector.push({
      kind: 'client',
      term: 'coverage-honesty',
      level: client.coverageLevel,
      label: `inspection depth (${client.coverageLevel}) — how much of the target the scan could see`,
      appliedPenalty: eCov,
    });

    score = Math.max(0, Math.min(100, Math.round(threatScore - eCap - eVer - eCov)));
  }
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
    threatScore,
    grade,
    band,
    gateCap,
    categorySubtotals,
    vector,
    gatesFired,
    methodologyVersion: METHODOLOGY_VERSION,
  };
}
