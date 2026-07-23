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

// Kinds whose match is a real accusation in a functional tool but only a
// DOCUMENTED example in a detector/guard tool or behind a defensive caveat.
// In that mention-vs-use context, and absent corroboration by a second injection
// kind, they are downgraded to a low heuristic rather than a high accusation —
// a scanner that flags "tool poisoning" on a legitimate injection-detector or a
// safety warning destroys client trust.
const MENTION_VS_USE_KINDS = new Set<string>(['override', 'command-in-prose', 'sensitive-target']);

// A tool whose very PURPOSE is to detect / scan / guard against malicious text:
// an override phrase in its metadata is its subject matter, not a planted payload.
const DEFENSIVE_TOOL_NAME =
  /detect|scan|guard|vet|sentinel|audit|complian|firewall|sanitiz|moderat|classif|injection|malicious|threat|is[_-]?safe|check[_-]?command|shield|policy/i;
// The phrase is framed as an example / quotation, or an explicit "do not obey" caveat.
const DEFENSIVE_FRAME =
  /such as|e\.?g\.?|for example|for instance|patterns? like|examples?\s*:|do not (obey|follow|execute|act on|comply)|ignore any (instructions|prompts?|text)|may (contain|include)|might contain|treat [^.]* as (untrusted|data)/i;

function isDefensiveContext(toolName: string | undefined, text: string): boolean {
  return DEFENSIVE_TOOL_NAME.test(toolName ?? '') || DEFENSIVE_FRAME.test(text);
}

// A nearby verb that turns a credential-path reference into actual access/exfil.
const EXFIL_VERB = /send|include|append|attach|paste|upload|exfiltrat|leak|return|reveal|copy|forward|\bread(s|ing)?\b|\baccess(es|ing)?\b|\bdump\b|\bopen\b|\bcat /i;
// A tool that legitimately operates ON ssh/credentials/config as its own subject.
const SELF_CREDENTIAL_TOOL = /ssh|known_hosts|credential|config|keychain|dotfile|\benv\b/i;
// The model is being TOLD to run the command — what makes a prose command an
// accusation rather than a documented example.
const MODEL_RUN_DIRECTIVE = /before (answer|respond)|you (must|should) (run|execute)|execute this (first|command)|run this (first|before|command)|silently (run|execute)|then run/i;
// A tool whose own function is running/deleting on a shell — a "rm -rf" in its
// description is documenting itself, not injecting.
const SHELL_TOOL_NAME = /command|shell|\bexec|terminal|bash|\brun_|process|delete|\brm\b|uninstall|cleanup/i;

export const injectionDetector: Detector = {
  id: 'injection',
  stage: 2,
  title: 'Prompt-injection / tool-poisoning heuristics',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    for (const field of collectTextFields(ctx.surface)) {
      const kindsHit = new Set<string>();
      // PASS 1 — detect every signal (populate kindsHit) and collect the ones
      // eligible to raise their own finding. Weak single-token shapes (emphasis,
      // self-ordering, context nouns, self-preference — `standalone: false`)
      // register their kind for the compound rule but are never collected here.
      const hits: { p: (typeof PATTERNS)[number]; match: string }[] = [];
      for (const p of PATTERNS) {
        if (!p.meta.channels.includes(field.channel as never)) continue;
        const match = firstMatch(p.regex, field.text);
        if (!match) continue;
        kindsHit.add(p.kind);
        if (p.meta.standalone !== false) hits.push({ p, match });
      }

      // ALL-CAPS shouting is a CORROBORATING signal only — standalone it fired
      // ~100% FP on acronyms, section headers ("PATTERN EXAMPLES:") and safety
      // warnings ("IMPORTANT: DO NOT …"). Feed the compound rule, never accuse.
      if (
        (field.channel === 'tool-description' ||
          field.channel === 'param-description' ||
          field.channel === 'server-instructions') &&
        longestAllCapsRun(field.text) >= ALLCAPS_RUN_WORDS
      ) {
        kindsHit.add('authority');
      }

      const toolName = field.location.name;
      const defensive = isDefensiveContext(toolName, field.text);

      // PASS 2 — raise each standalone finding, applying mention-vs-use downgrades
      // now that kindsHit is complete (so corroboration can be judged).
      for (const { p, match } of hits) {
        let severity: Severity = p.meta.baseSeverity;
        let confidence = p.meta.baseConfidence;
        const corroborated = [...kindsHit].some((k) => k !== p.kind);

        if (MENTION_VS_USE_KINDS.has(p.kind) && !corroborated) {
          if (p.kind === 'sensitive-target') {
            // A credential-path reference is only HIGH when a read/exfil verb sits
            // near it AND the tool is not itself an ssh/credentials/config utility
            // (whose subject legitimately IS that path).
            if (!EXFIL_VERB.test(field.text) || SELF_CREDENTIAL_TOOL.test(toolName ?? '')) {
              severity = 'low';
              confidence = 'heuristic';
            }
          } else if (p.kind === 'command-in-prose') {
            // A shell command is a HIGH accusation only when the model is told to
            // RUN it. In a shell/exec/delete tool documenting its own behaviour,
            // or a scanner, a bare "rm -rf" is an example — downgrade.
            if (!MODEL_RUN_DIRECTIVE.test(field.text) && (defensive || SHELL_TOOL_NAME.test(toolName ?? ''))) {
              severity = 'low';
              confidence = 'heuristic';
            }
          } else if (defensive) {
            // An override phrase documented in a detector/guard tool or guarded by
            // a "do not obey" caveat is being described, not planted.
            severity = 'low';
            confidence = 'heuristic';
          }
        }

        findings.push({
          ruleId: p.id,
          title: p.meta.title,
          category: 'injection',
          severity,
          confidence,
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
      // at least one other poisoning signal (now including the weak shapes and
      // ALL-CAPS that no longer accuse on their own). A mere sensitive-target
      // reference or plain emphasis is not enough.
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
