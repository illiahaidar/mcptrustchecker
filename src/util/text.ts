/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Text extraction & normalization helpers shared by the lexical detectors.
 * The point of `collectTextFields` is that every human/LLM-facing string in the
 * surface is scanned uniformly, each carrying a precise location so findings can
 * point at exactly which field is poisoned.
 */

import type { FindingLocation, JsonSchema, ServerSurface } from '../types.js';
import { INJECTION_PATTERNS } from '../data/injectionPatterns.js';

export interface TextField {
  text: string;
  location: FindingLocation;
  /** Which injection channel this field belongs to. */
  channel: 'tool-description' | 'param-description' | 'server-instructions' | 'other';
}

/** Walk an inputSchema collecting every `description` string with a JSON path. */
export function collectSchemaStrings(
  schema: JsonSchema | undefined,
  basePath: string,
): { path: string; text: string }[] {
  const out: { path: string; text: string }[] = [];
  if (!schema || typeof schema !== 'object') return out;

  // Depth cap: an untrusted manifest can nest `properties`/`items` arbitrarily
  // deep; bound the recursion so a hostile schema can't overflow the stack.
  const MAX_DEPTH = 64;
  const visit = (node: JsonSchema | undefined, path: string, depth: number): void => {
    if (!node || typeof node !== 'object' || depth > MAX_DEPTH) return;
    if (typeof node.description === 'string' && node.description.length > 0) {
      out.push({ path: `${path}.description`, text: node.description });
    }
    if (typeof node.title === 'string' && node.title.length > 0) {
      out.push({ path: `${path}.title`, text: node.title });
    }
    if (Array.isArray(node.enum)) {
      for (const [i, v] of node.enum.entries()) {
        if (typeof v === 'string') out.push({ path: `${path}.enum[${i}]`, text: v });
      }
    }
    if (node.properties) {
      for (const [key, child] of Object.entries(node.properties)) {
        visit(child, `${path}.properties.${key}`, depth + 1);
      }
    }
    if (node.items && !Array.isArray(node.items)) visit(node.items, `${path}.items`, depth + 1);
    if (Array.isArray(node.items)) node.items.forEach((it, i) => visit(it, `${path}.items[${i}]`, depth + 1));
  };

  visit(schema, basePath, 0);
  return out;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Collect every scannable text field across the whole surface. Defensive: only
 * string values are emitted and non-object tools/prompts/resources are skipped,
 * so a caller that hands us a hand-built (unnormalized) surface — or a live
 * server returning junk — can never crash a text detector.
 */
export function collectTextFields(surface: ServerSurface): TextField[] {
  const fields: TextField[] = [];
  // Cap each field's length: a legit MCP description is never this long, and an
  // uncapped multi-MB field is a DoS vector for the text detectors' regexes.
  const MAX_FIELD = 100_000;
  const add = (text: unknown, location: TextField['location'], channel: TextField['channel']): void => {
    if (typeof text === 'string' && text.length > 0) {
      fields.push({ text: text.length > MAX_FIELD ? text.slice(0, MAX_FIELD) : text, location, channel });
    }
  };

  add(surface.server?.name, { kind: 'server', field: 'name' }, 'other');
  add(surface.server?.instructions, { kind: 'server', field: 'instructions' }, 'server-instructions');

  for (const tool of Array.isArray(surface.tools) ? surface.tools : []) {
    if (!isObj(tool)) continue;
    const name = typeof tool.name === 'string' ? tool.name : undefined;
    add(tool.name, { kind: 'tool', name, field: 'name' }, 'other');
    add(tool.title, { kind: 'tool', name, field: 'title' }, 'tool-description');
    add(tool.description, { kind: 'tool', name, field: 'description' }, 'tool-description');
    for (const s of collectSchemaStrings(tool.inputSchema, 'inputSchema')) {
      add(s.text, { kind: 'tool', name, field: s.path }, 'param-description');
    }
  }

  for (const prompt of Array.isArray(surface.prompts) ? surface.prompts : []) {
    if (!isObj(prompt)) continue;
    const name = typeof prompt.name === 'string' ? prompt.name : undefined;
    add(prompt.description, { kind: 'prompt', name, field: 'description' }, 'tool-description');
    for (const arg of Array.isArray(prompt.arguments) ? prompt.arguments : []) {
      if (isObj(arg)) add(arg.description, { kind: 'prompt', name, field: `arguments.${String(arg.name)}.description` }, 'param-description');
    }
  }

  for (const res of Array.isArray(surface.resources) ? surface.resources : []) {
    if (!isObj(res)) continue;
    const name = typeof res.name === 'string' ? res.name : typeof res.uri === 'string' ? res.uri : undefined;
    add(res.description, { kind: 'resource', name, field: 'description' }, 'tool-description');
  }

  return fields;
}

/** Lowercased text with punctuation collapsed to spaces, for keyword matching. */
export function normalizeForMatch(text: string): string {
  return text
    .toLowerCase()
    .replace(/[_\-./]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Common technical acronyms / HTTP verbs that are legitimately upper-case and
// must not count toward a "shouting" run (e.g. "GET, POST, PUT, DELETE").
const TECH_ACRONYMS = new Set([
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT',
  'API', 'URL', 'URI', 'JSON', 'HTML', 'XML', 'CSV', 'YAML', 'SQL', 'HTTP', 'HTTPS',
  'REST', 'RPC', 'GRPC', 'ID', 'UUID', 'UI', 'UX', 'OK', 'CRUD', 'JWT', 'CORS',
  'CPU', 'GPU', 'RAM', 'PDF', 'PNG', 'JPG', 'GIF', 'SVG', 'TCP', 'UDP', 'DNS',
  'SSH', 'TLS', 'SSL', 'AWS', 'GCP', 'IAM', 'S3', 'EC2', 'K8S', 'CI', 'CD', 'MCP',
  'AND', 'OR', 'NOT', 'IN', 'IS', 'TODO', 'FIXME', 'NOTE', 'WARN', 'ISO', 'UTC',
]);

/** Count the longest run of consecutive shouted words (excluding tech acronyms). */
export function longestAllCapsRun(text: string): number {
  if (typeof text !== 'string') return 0;
  const words = text.split(/\s+/);
  let best = 0;
  let run = 0;
  for (const w of words) {
    const letters = w.replace(/[^A-Za-z]/g, '');
    // Count only genuine SHOUTING — a run of long all-caps WORDS. Everything an
    // audit found firing falsely is excluded structurally: acronyms & cloud/
    // hardware IDs are short (GPU, NUMA, ECR, CUDA, ≤6 letters) or carry digits
    // (MI300X, HBM3); documentation section headers end in a colon ("EXAMPLES:").
    const shouting =
      letters.length > 6 &&
      letters === letters.toUpperCase() &&
      !/\d/.test(w) &&
      !/:$/.test(w) &&
      !TECH_ACRONYMS.has(letters);
    if (shouting) {
      run += 1;
      best = Math.max(best, run);
    } else {
      run = 0;
    }
  }
  return best;
}

/**
 * Detect a long base64-looking blob (potential encoded payload). Deliberately
 * rejects pure-hex runs (git SHAs, dash-stripped UUIDs, account/hex IDs) and
 * requires genuine base64 shape (a padding/base64 symbol, or real mixed case
 * with digits), so ordinary identifiers in descriptions don't misfire.
 */
export function hasBase64Blob(text: string): boolean {
  if (typeof text !== 'string') return false;
  // Bounded quantifier + input cap: an unbounded {24,} over a multi-MB run can
  // overflow the regex engine's stack.
  const t = text.length > 100_000 ? text.slice(0, 100_000) : text;
  // Scan every candidate run (not just the first) so a genuine blob isn't masked
  // by an earlier slash-separated word list appearing before it.
  for (const m of t.matchAll(/(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{24,4096}={0,2})(?:[^A-Za-z0-9+/=]|$)/g)) {
    const blob = m[1]!;
    if (/^[0-9a-f]+$/i.test(blob)) continue; // pure hex → an ID, not base64
    // `+` and `=` are prose-rare and a strong base64 signal. `/` alone is NOT —
    // it is common in prose ("and/or", paths, slash-separated word lists like
    // "methodology/results/structure"), so it must not qualify on its own.
    const hasStrongSymbol = /[+=]/.test(blob);
    // Without a strong symbol, require the high-entropy mix real encoded data has
    // (lower + upper + digit). A slash-delimited word list is letters-only → excluded.
    const mixedCaseDigits = /[a-z]/.test(blob) && /[A-Z]/.test(blob) && /[0-9]/.test(blob);
    if (hasStrongSymbol || mixedCaseDigits) return true;
  }
  return false;
}

/** Re-export the compiled injection patterns as case-insensitive/global regexes. */
export function compiledInjectionPatterns(): {
  id: string;
  kind: string;
  regex: RegExp;
  meta: (typeof INJECTION_PATTERNS)[number];
}[] {
  return INJECTION_PATTERNS.map((p) => ({
    id: p.id,
    kind: p.kind,
    regex: new RegExp(p.pattern.source, 'gi'),
    meta: p,
  }));
}
