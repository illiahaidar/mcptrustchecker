/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 2 — Content injection heuristics (tool poisoning / line jumping /
 * shadowing). Runs the pattern lexicon across four channels, then escalates
 * when multiple poisoning signals co-occur in one field — the shape of a real
 * tool-poisoning attack rather than an incidental keyword.
 */

import type { Detector, DetectorContext, Finding, Severity } from '../types.js';
import { collectTextFields } from '../util/text.js';
import { compiledInjectionPatterns, longestAllCapsRun, hasBase64Blob } from '../util/text.js';
import {
  ALLCAPS_RUN_WORDS,
  SECRET_PATTERNS,
  SUSPICIOUS_PARAM_NAMES,
  SUSPICIOUS_URL_HOST,
  SUSPICIOUS_URL_PATH,
  URL_IP_LITERAL,
} from '../data/injectionPatterns.js';

const PATTERNS = compiledInjectionPatterns();

function firstMatch(regex: RegExp, text: string): string | undefined {
  const m = text.match(regex);
  return m ? m[0] : undefined;
}

export const injectionDetector: Detector = {
  id: 'injection',
  stage: 2,
  title: 'Prompt-injection / tool-poisoning heuristics',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    for (const field of collectTextFields(ctx.surface)) {
      const kindsHit = new Set<string>();

      for (const p of PATTERNS) {
        if (!p.meta.channels.includes(field.channel as never)) continue;
        const match = firstMatch(p.regex, field.text);
        if (!match) continue;
        kindsHit.add(p.kind);
        findings.push({
          ruleId: p.id,
          title: p.meta.title,
          category: 'injection',
          severity: p.meta.baseSeverity,
          confidence: p.meta.baseConfidence,
          description:
            `${p.meta.title} detected in the ${field.location.field ?? 'text'} of ` +
            `${field.location.kind}${field.location.name ? ` "${field.location.name}"` : ''}. ` +
            `Instruction-like content in tool metadata is executed by the model, not the human, and is the ` +
            `primary tool-poisoning vector.`,
          remediation:
            'Tool descriptions should describe behavior, not instruct the assistant. Treat imperative / ' +
            'secrecy / sequencing language in metadata as hostile.',
          location: field.location,
          evidence: match.slice(0, 160),
          owasp: 'LLM01:2025 Prompt Injection',
          data: { kind: p.kind },
        });
      }

      // Escalation to CRITICAL requires a genuinely malicious signal — secrecy
      // (conceal from the user) or an instruction override — co-occurring with
      // at least one other poisoning signal. A mere sensitive-target reference
      // is NOT enough (legit tools reference credentials/context), nor is plain
      // emphasis + sequencing ("IMPORTANT: call X first").
      const strongSignal = kindsHit.has('secrecy') || kindsHit.has('override');
      if (strongSignal && kindsHit.size >= 2) {
        findings.push({
          ruleId: 'MTC-INJ-POISON',
          title: 'Compound tool-poisoning pattern',
          category: 'injection',
          severity: 'critical',
          confidence: 'strong',
          description:
            `Multiple tool-poisoning signals co-occur in a single field (${[...kindsHit].join(', ')}), including a ` +
            `concealment / override / sensitive-target directive. Together they form an instruction aimed at the ` +
            `model — the canonical tool-poisoning shape, not ordinary documentation.`,
          remediation: 'Do not install this server; the metadata is engineered to manipulate the assistant.',
          location: field.location,
          evidence: field.text.slice(0, 200),
          owasp: 'LLM01:2025 Prompt Injection',
          data: { kinds: [...kindsHit] },
        });
      }

      // ALL-CAPS shouting (weak signal, contextual).
      if (
        (field.channel === 'tool-description' ||
          field.channel === 'param-description' ||
          field.channel === 'server-instructions') &&
        longestAllCapsRun(field.text) >= ALLCAPS_RUN_WORDS
      ) {
        findings.push({
          ruleId: 'MTC-INJ-CAPS',
          title: 'Excessive ALL-CAPS emphasis in metadata',
          category: 'injection',
          severity: 'low' as Severity,
          confidence: 'heuristic',
          description: 'A run of shouted words is a common way to give injected instructions false authority.',
          location: field.location,
          evidence: field.text.slice(0, 120),
        });
      }

      // Base64 blob in prose paired with an explicit decode/execute verb.
      // Requires an actual DECODE verb near a blob — "execute"/"eval" describing
      // a tool's normal function (e.g. "execute batched operations") must not match.
      if (
        field.channel !== 'other' &&
        hasBase64Blob(field.text) &&
        /\b(decode|base64|atob|b64decode|un-?base64)\b/i.test(field.text)
      ) {
        findings.push({
          ruleId: 'MTC-INJ-ENC-2',
          title: 'Encoded blob paired with a decode/execute instruction',
          category: 'injection',
          severity: 'high',
          confidence: 'strong',
          description: 'A long base64-looking blob appears alongside a decode/execute instruction — a common way to hide a payload from reviewers.',
          location: field.location,
          evidence: field.text.slice(0, 160),
          owasp: 'LLM01:2025 Prompt Injection',
        });
      }

      // Embedded secret VALUE (a real credential, not merely a reference).
      for (const sp of SECRET_PATTERNS) {
        const m = field.text.match(sp.pattern);
        if (m) {
          findings.push({
            ruleId: 'MTC-INJ-SECRET-1',
            title: `Embedded ${sp.label} in ${field.location.field ?? 'metadata'}`,
            category: 'exfiltration',
            severity: 'high',
            confidence: 'confirmed',
            description:
              `A live-looking ${sp.label} is embedded in the ${field.location.field ?? 'metadata'} of ` +
              `${field.location.kind}${field.location.name ? ` "${field.location.name}"` : ''}. Hardcoded ` +
              `credentials in server metadata leak to every client that lists this server.`,
            remediation: 'Remove the credential and rotate it; never ship secrets in tool metadata.',
            location: field.location,
            evidence: `${sp.label}: ${m[0]!.slice(0, 4)}…(redacted)`,
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
            data: { secretType: sp.id },
          });
        }
      }

      // Suspicious external URL in metadata — a hardcoded webhook/paste/exfil
      // endpoint or raw IP in a tool description is a data-exfiltration channel
      // (the malicious-URL tool-poisoning move: "send the result to …").
      for (const um of field.text.matchAll(/\bhttps?:\/\/([^\s/"'`)\]]+)(\/[^\s"'`)]*)?/gi)) {
        const host = (um[1] ?? '').toLowerCase();
        const rest = um[2] ?? '';
        if (SUSPICIOUS_URL_HOST.test(host) || URL_IP_LITERAL.test(host) || SUSPICIOUS_URL_PATH.test(host + rest)) {
          findings.push({
            ruleId: 'MTC-INJ-URL-1',
            title: 'Suspicious external URL in tool metadata',
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'strong',
            description:
              `A hardcoded link to a request/paste/webhook sink (or raw IP) appears in the ` +
              `${field.location.field ?? 'metadata'} of ${field.location.kind}` +
              `${field.location.name ? ` "${field.location.name}"` : ''}. Tool metadata pointing the model at a ` +
              `fixed external endpoint is a data-exfiltration channel — the classic "send the output to …" poisoning.`,
            remediation: 'A legitimate tool takes its destination as a validated parameter; it does not hardcode a webhook/paste sink in its description.',
            location: field.location,
            evidence: um[0].slice(0, 120),
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
          });
          break; // one per field is enough
        }
      }
    }

    // Suspicious hidden-parameter names.
    for (const tool of ctx.surface.tools) {
      if (!tool || typeof tool !== 'object') continue;
      const props = tool.inputSchema?.properties ?? {};
      for (const paramName of Object.keys(props)) {
        if (SUSPICIOUS_PARAM_NAMES.includes(paramName.toLowerCase())) {
          findings.push({
            ruleId: 'MTC-INJ-PARAM',
            title: `Suspicious hidden-channel parameter "${paramName}"`,
            category: 'injection',
            severity: 'medium',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" exposes a parameter named "${paramName}", a name frequently used as a ` +
              `hidden exfiltration channel (the model is told to stuff context/history/secrets into it).`,
            remediation: 'Verify what this parameter is actually used for; hidden "context"/"note" params are a red flag.',
            location: { kind: 'tool', name: tool.name, field: `inputSchema.properties.${paramName}` },
            owasp: 'LLM01:2025 Prompt Injection',
            data: { param: paramName },
          });
        }
      }
    }

    return findings;
  },
};
