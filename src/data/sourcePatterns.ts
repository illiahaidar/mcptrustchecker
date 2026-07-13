/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Implementation-level sink lexicon. Tool metadata says what a server *claims*
 * to do; these patterns read what its code *actually does* — the dangerous
 * sinks (arbitrary execution, egress, secret handling) that a poisoned or
 * negligent server hides in its implementation. Deterministic, no LLM.
 *
 * Kept high-precision: each pattern anchors on a real dangerous API, and the
 * detector escalates when attacker-influenced data can reach it.
 */

import type { Confidence, Severity } from '../types.js';

export interface SourcePattern {
  id: string;
  title: string;
  /** Language hint for the finding text. */
  lang: 'js' | 'py' | 'any';
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  category: 'permissions' | 'exfiltration' | 'injection';
  why: string;
}

/** File extensions we treat as scannable server source. */
export const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.py']);

export const SOURCE_PATTERNS: SourcePattern[] = [
  // ── Arbitrary code execution ────────────────────────────────────────────────
  {
    id: 'MTC-SRC-001',
    title: 'Dynamic code execution in server code',
    lang: 'any',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|vm\.(?:runIn\w+|compileFunction)\s*\(|\bexec\s*\(\s*compile\s*\(/,
    severity: 'high',
    confidence: 'strong',
    category: 'permissions',
    why: 'Evaluating strings as code is the most direct RCE primitive; if any tool input reaches it, the server executes attacker-chosen code.',
  },
  // ── Shell / command execution ───────────────────────────────────────────────
  {
    id: 'MTC-SRC-002',
    title: 'Shell/command execution in server code',
    lang: 'any',
    pattern: /child_process|\bexecSync\s*\(|\bexec\s*\(|\bspawn(?:Sync)?\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\(|\bshell\s*[:=]\s*True/,
    severity: 'high',
    confidence: 'strong',
    category: 'permissions',
    why: 'Spawning a shell/process is command-execution capability; with unsanitized tool input it is command injection / RCE.',
  },
  // ── Outbound egress to a hardcoded external host ────────────────────────────
  {
    id: 'MTC-SRC-003',
    title: 'Hardcoded egress to an external endpoint',
    lang: 'any',
    // fetch/axios/requests/urllib to a literal http(s) URL that is NOT localhost.
    pattern: /(?:fetch|axios(?:\.\w+)?|requests\.\w+|urllib\.request\.urlopen|https?\.request|got|node-fetch)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"`]+['"`]/,
    severity: 'medium',
    confidence: 'strong',
    category: 'exfiltration',
    why: 'A hardcoded outbound call to a fixed external host inside server code is a classic exfiltration/telemetry channel — especially paired with reads of local data.',
  },
  // ── Obfuscation / hidden payloads ───────────────────────────────────────────
  {
    id: 'MTC-SRC-004',
    title: 'Obfuscated / encoded payload in server code',
    lang: 'any',
    pattern: /(?:eval|exec|new Function|Function)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode)\b|atob\s*\([^)]*\)\s*\)?\s*(?:\)|;)?\s*.{0,20}\beval|Buffer\.from\s*\([^)]*,\s*['"`]base64['"`]\s*\)[^;]{0,40}(?:eval|Function|exec)|base64\.b64decode\s*\([^)]*\)[^;]{0,40}(?:exec|eval)|(?:\\x[0-9a-fA-F]{2}){8,}|String\.fromCharCode\s*\((?:\s*\d+\s*,){8,}/,
    severity: 'high',
    confidence: 'strong',
    category: 'injection',
    why: 'Decoding an encoded blob and executing it is how malicious logic is hidden from human review of the source.',
  },
  // ── Dynamic module loading ──────────────────────────────────────────────────
  {
    id: 'MTC-SRC-005',
    title: 'Dynamic module load from a non-literal',
    lang: 'any',
    pattern: /\brequire\s*\(\s*(?!['"`])[A-Za-z_$][\w$.]*\s*\)|\bimport\s*\(\s*(?!['"`])[A-Za-z_$][\w$.]*\s*\)|__import__\s*\(\s*(?!['"`])/,
    severity: 'medium',
    confidence: 'heuristic',
    category: 'permissions',
    why: 'Loading a module chosen at runtime (from a variable) can pull in and run attacker-influenced code paths.',
  },
  // ── Sensitive filesystem / environment reads ────────────────────────────────
  {
    id: 'MTC-SRC-006',
    title: 'Reads a sensitive credential path or dumps the environment',
    lang: 'any',
    pattern: /~\/\.ssh|id_rsa\b|\.aws\/credentials|\.config\/gcloud|\.netrc\b|\.docker\/config\.json|JSON\.stringify\s*\(\s*process\.env\s*\)|\bdict\s*\(\s*os\.environ\s*\)|json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ/,
    severity: 'high',
    confidence: 'strong',
    category: 'exfiltration',
    why: 'Reading private keys / cloud credentials, or serializing the whole environment, is a sensitive-data source that becomes exfiltration when combined with any egress.',
  },
  // ── Unsafe deserialization ──────────────────────────────────────────────────
  {
    id: 'MTC-SRC-007',
    title: 'Unsafe deserialization',
    lang: 'any',
    pattern: /\bpickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|node-serialize|\bunserialize\s*\(|marshal\.loads?\s*\(/,
    severity: 'high',
    confidence: 'strong',
    category: 'permissions',
    why: 'Deserializing untrusted data with these APIs can execute arbitrary code (a well-known RCE gadget class).',
  },
];
