/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability extraction: derive each tool's roles (untrusted-input,
 * sensitive-source, external-sink, code-exec, file-write) from its name,
 * description verbs, and parameter shape. This is the substrate the toxic-flow
 * graph runs over. It is deliberately derived from behavior, never from the
 * server's self-declared `annotations` (which are untrusted).
 */

import type { CapabilityTag, ResolvedConfig, ServerSurface, ToolCapability, ToolDef } from '../types.js';
import { CAPABILITY_SIGNALS, PARAM_NAME_SIGNALS } from '../data/capabilityLexicon.js';
import { normalizeForMatch } from './text.js';

function tokenize(text: string): Set<string> {
  return new Set(normalizeForMatch(text).split(' ').filter(Boolean));
}

function keywordMatches(haystack: string, tokens: Set<string>, keyword: string): boolean {
  const k = normalizeForMatch(keyword);
  if (k.includes(' ')) return haystack.includes(k);
  return tokens.has(k);
}

function paramNames(tool: ToolDef): string[] {
  const props = tool.inputSchema?.properties;
  if (!props) return [];
  return Object.keys(props);
}

/** Extract capability tags + evidence for a single tool. */
export function extractToolCapability(tool: ToolDef): ToolCapability {
  const name = typeof tool?.name === 'string' ? tool.name : '';
  const desc = typeof tool?.description === 'string' ? tool.description : '';
  const haystack = normalizeForMatch(`${name} ${desc}`);
  const tokens = tokenize(`${name} ${desc}`);
  const reasons: Partial<Record<CapabilityTag, string[]>> = {};
  const tags = new Set<CapabilityTag>();

  const addReason = (tag: CapabilityTag, why: string): void => {
    tags.add(tag);
    (reasons[tag] ??= []).push(why);
  };

  for (const sig of CAPABILITY_SIGNALS) {
    for (const kw of sig.keywords) {
      if (keywordMatches(haystack, tokens, kw)) {
        addReason(sig.tag, `keyword "${kw}"`);
        break; // one reason per signal is enough
      }
    }
  }

  const pnames = paramNames(tool).map((n) => n.toLowerCase());
  const pTokens = new Set(pnames.flatMap((n) => n.split(/[^a-z0-9]+/i).filter(Boolean)));
  for (const sig of PARAM_NAME_SIGNALS) {
    for (const pn of sig.names) {
      if (pTokens.has(pn)) {
        addReason(sig.tag, `parameter "${pn}"`);
        break;
      }
    }
  }

  return { tool: name, tags: [...tags], reasons };
}

/** Extract capabilities for every tool in a surface (non-object tools skipped). */
export function extractCapabilities(surface: ServerSurface, _config: ResolvedConfig): ToolCapability[] {
  const tools = Array.isArray(surface.tools) ? surface.tools : [];
  return tools.filter((t): t is ToolDef => Boolean(t) && typeof t === 'object').map(extractToolCapability);
}

/** Tags that can act as an exfiltration/impact sink. */
export const SINK_TAGS: CapabilityTag[] = ['external-sink', 'code-exec'];

/** True if a capability set can serve as an external sink. */
export function isSink(tags: CapabilityTag[]): boolean {
  return tags.some((t) => SINK_TAGS.includes(t));
}
