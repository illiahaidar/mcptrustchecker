/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 4b — Implementation-level analysis.
 *
 * Metadata detectors read what a server *claims*. This one reads what its code
 * *does*: when the server's source is available (a local package directory or an
 * extracted tarball), it scans for dangerous sinks — arbitrary execution, shell
 * spawning, hardcoded egress, obfuscated payloads, credential reads. Fully
 * deterministic; no LLM, no execution of the code.
 */

import type { Detector, DetectorContext, Finding, SourceFile } from '../types.js';
import { SOURCE_PATTERNS } from '../data/sourcePatterns.js';
import { SECRET_PATTERNS } from '../data/injectionPatterns.js';

const MAX_FINDINGS_PER_RULE = 10; // don't drown the report on a big codebase

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line += 1;
  return line;
}

export const sourceDetector: Detector = {
  id: 'source',
  stage: 4,
  title: 'Implementation-level source analysis',
  run(ctx: DetectorContext): Finding[] {
    const files: SourceFile[] = Array.isArray(ctx.surface.sourceFiles) ? ctx.surface.sourceFiles : [];
    if (!files.length) return [];
    const findings: Finding[] = [];
    const perRule = new Map<string, number>();

    for (const f of files) {
      if (!f || typeof f.content !== 'string') continue;
      const path = typeof f.path === 'string' ? f.path : 'source';

      for (const p of SOURCE_PATTERNS) {
        const seen = perRule.get(p.id) ?? 0;
        if (seen >= MAX_FINDINGS_PER_RULE) continue;
        const m = f.content.match(p.pattern);
        if (!m || m.index === undefined) continue;
        perRule.set(p.id, seen + 1);
        findings.push({
          ruleId: p.id,
          title: `${p.title} (${path})`,
          category: p.category,
          severity: p.severity,
          confidence: p.confidence,
          description:
            `In the server's implementation (\`${path}:${lineOf(f.content, m.index)}\`): ${p.why} ` +
            `This is read from the code itself — not from the tool description — so a poisoned server cannot hide it behind honest-looking metadata.`,
          remediation:
            'Review this call path: confirm it never receives unsanitized tool input, constrain it, or remove it. ' +
            'Treat a server whose code reaches these sinks as high-capability regardless of what its tools claim.',
          location: { kind: 'server', name: path },
          evidence: m[0].slice(0, 160),
          owasp: p.category === 'exfiltration' ? 'LLM02:2025 Sensitive Information Disclosure' : 'LLM05:2025 Improper Output Handling',
          data: { rule: p.id, file: path, line: lineOf(f.content, m.index) },
        });
      }

      // Embedded credential VALUE hardcoded in source (not just referenced).
      const seenSecret = perRule.get('MTC-SRC-008') ?? 0;
      if (seenSecret < MAX_FINDINGS_PER_RULE) {
        for (const sp of SECRET_PATTERNS) {
          const m = f.content.match(sp.pattern);
          if (!m || m.index === undefined) continue;
          perRule.set('MTC-SRC-008', seenSecret + 1);
          findings.push({
            ruleId: 'MTC-SRC-008',
            title: `Hardcoded ${sp.label} in server code (${path})`,
            category: 'exfiltration',
            severity: 'high',
            confidence: 'confirmed',
            description:
              `A live-looking ${sp.label} is hardcoded in \`${path}:${lineOf(f.content, m.index)}\`. Secrets in source ` +
              `ship to everyone who installs the package and are a direct credential leak.`,
            remediation: 'Remove the secret, rotate it, and load credentials from the environment or a secret store.',
            location: { kind: 'server', name: path },
            evidence: `${sp.label}: ${m[0]!.slice(0, 4)}…(redacted)`,
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
            data: { secretType: sp.id, file: path, line: lineOf(f.content, m.index) },
          });
          break; // one secret finding per file is enough
        }
      }
    }
    return findings;
  },
};
