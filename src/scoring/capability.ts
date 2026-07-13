/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability (blast-radius) rating — the second axis, independent of the trust
 * grade. It answers "how much could this server do if the model driving it were
 * prompt-injected?" A legitimate, well-behaved server can still be high- or
 * critical-capability; that is not a mark against its trustworthiness, it is
 * information for deciding how much access to grant.
 */

import type { CapabilityLevel, CapabilityProfile, CapabilityTag, ToolCapability, ToxicFlow } from '../types.js';

const ORDER: CapabilityLevel[] = ['minimal', 'moderate', 'high', 'critical'];

function atLeast(current: CapabilityLevel, candidate: CapabilityLevel): CapabilityLevel {
  return ORDER.indexOf(candidate) > ORDER.indexOf(current) ? candidate : current;
}

export function computeCapabilityProfile(capabilities: ToolCapability[], flows: ToxicFlow[]): CapabilityProfile {
  const tagSet = new Set<CapabilityTag>(capabilities.flatMap((c) => c.tags));
  const has = (t: CapabilityTag): boolean => tagSet.has(t);
  const reasons: string[] = [];
  let level: CapabilityLevel = 'minimal';

  const bump = (candidate: CapabilityLevel, reason: string): void => {
    level = atLeast(level, candidate);
    reasons.push(reason);
  };

  if (has('untrusted-input')) bump('moderate', 'ingests untrusted external content (a prompt-injection entry point)');
  if (has('external-sink')) bump('moderate', 'can send data / act on an external service');
  if (has('file-write')) bump('moderate', 'can create, modify or delete files');
  if (has('sensitive-source')) bump('moderate', 'reads sensitive or local data');

  if (has('sensitive-source') && (has('external-sink') || has('code-exec'))) {
    bump('high', 'has a read → egress path (a data-exfiltration surface)');
  }
  if (has('code-exec')) bump('high', 'can execute shell commands or code');

  const roleComplete = (f: ToxicFlow): boolean =>
    f.untrustedInput.length > 0 && f.sensitiveSource.length > 0 && f.externalSink.length > 0;
  const selfContained = flows.some((f) => f.selfContained && roleComplete(f));
  const crossTrifecta = flows.some((f) => !f.selfContained && roleComplete(f));

  if (crossTrifecta) bump('high', 'untrusted-input, sensitive-source and egress co-exist across tools (toxic-flow surface)');
  if (selfContained) bump('critical', 'a single tool completes the exfiltration trifecta by itself');
  if (has('code-exec') && has('untrusted-input')) bump('critical', 'untrusted input can reach code execution');

  // De-duplicate reasons while preserving order.
  const seen = new Set<string>();
  const uniqueReasons = reasons.filter((r) => (seen.has(r) ? false : (seen.add(r), true)));

  return { level, reasons: uniqueReasons, tags: [...tagSet] };
}
