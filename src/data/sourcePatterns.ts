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

/**
 * Paths that ship inside a package but are NOT the running server: test suites,
 * benchmarks, examples, and the maintainer's own build/release tooling.
 *
 * This distinction matters for the *threat* rules. "Untrusted input reaches a
 * shell" is a claim about the server's runtime; a release script that runs
 * `npm publish ${tag}` on the maintainer's laptop has no tool input and no MCP
 * client — flagging it says nothing about the server a user would install.
 * (Capability rules still apply everywhere: the code is genuinely present.)
 *
 * Install-time hooks are NOT excused by this: a malicious `postinstall` is
 * caught by MTC-SUP-010 regardless of which directory the script lives in.
 */
const NON_RUNTIME_DIR = /(^|\/)(?:tests?|__tests__|spec|specs|benchmarks?|bench|examples?|samples?|fixtures?|__mocks__|mocks?|e2e|docs?|website|scripts|tools|\.github)(\/|$)/i;
const NON_RUNTIME_FILE = /(^|\/)[^/]*(?:\.test|\.spec|\.bench|_test|_spec)\.[a-z]+$/i;

/** True when a path is packaging/dev tooling rather than the server itself. */
export function isNonRuntimePath(path: string): boolean {
  const p = String(path ?? '');
  return NON_RUNTIME_DIR.test(p) || NON_RUNTIME_FILE.test(p);
}

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
    // Bare `exec(` / `spawn(` must not be preceded by a dot: `regex.exec(str)`
    // (RegExp.prototype.exec) and `pool.spawn(` are everyday, harmless calls.
    // Real process spawning is still caught: the `child_process` module token
    // matches the import, and Python's builtins are dot-free by nature.
    pattern: /child_process|\bexecSync\s*\(|(?<!\.)\bexec\s*\(|(?<!\.)\bspawn(?:Sync)?\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\(|\bshell\s*[:=]\s*True/,
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
  // ── Input FLOW into a sink (threat, not mere capability) ────────────────────
  // The capability rules above fire on the mere PRESENCE of a sink. These two
  // fire only when the code visibly builds the sink's argument from a
  // non-literal — concatenation or template interpolation into a command, or
  // eval of a variable. That is the classic injection signature, and it is what
  // separates a legitimate `exec('git status')` from `exec('curl '+userInput)`.
  {
    id: 'MTC-SRC-009',
    title: 'Untrusted input concatenated into a command sink',
    lang: 'any',
    // exec/spawn/system/popen whose argument is a template with ${…}, or a
    // string literal followed by `+`, or an identifier followed by `+ "…"`.
    // A single validated variable arg (`exec(cmd)`) is NOT matched — only a
    // visibly-assembled command is. `regex.exec(str)` never matches (no concat).
    pattern: /(?:exec|execSync|spawn|spawnSync|system|popen|check_output)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$.[\]]*\s*\+\s*['"`])/,
    // Medium, not high: static analysis can see that the command is ASSEMBLED,
    // but not whether the assembled part is attacker-reachable. Most MCP servers
    // are CLI wrappers, and interpolating their own constants (`${ADB} devices`,
    // `xcrun simctl boot ${udid}`) is how they work at all. This is a genuine
    // injection *precondition* worth surfacing — not proof of a flow, and not
    // grounds on its own for a failing grade.
    severity: 'medium',
    confidence: 'strong',
    category: 'injection',
    why: 'A shell/process command assembled from concatenated or interpolated values is command injection when any part is attacker-influenced — the OWASP canonical RCE flow. Verify what reaches the interpolated value.',
  },
  {
    id: 'MTC-SRC-010',
    title: 'Dynamic evaluation of a non-literal value',
    lang: 'any',
    // eval(/Function( applied to something that is NOT a plain string literal —
    // i.e. a variable or expression. eval("2+2") is not matched; eval(x) is.
    pattern: /\b(?:eval|new\s+Function)\s*\(\s*(?!['"`)\s])/,
    severity: 'high',
    confidence: 'strong',
    category: 'injection',
    why: 'Evaluating a runtime value as code (rather than a fixed literal) executes whatever reaches it — a direct RCE primitive, and almost never necessary in legitimate code.',
  },
  // ── Unsafe deserialization ──────────────────────────────────────────────────
  {
    id: 'MTC-SRC-007',
    title: 'Unsafe deserialization',
    lang: 'any',
    pattern: /\bpickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|node-serialize|\bunserialize\s*\(|marshal\.loads?\s*\(/,
    // Medium, not high: presence alone cannot tell whether the data being
    // deserialized is attacker-reachable. Choosing the unsafe API where a safe
    // one exists is a negligence signal worth surfacing — not an F-driver.
    severity: 'medium',
    confidence: 'strong',
    category: 'permissions',
    why: 'Deserializing untrusted data with these APIs can execute arbitrary code (a well-known RCE gadget class).',
  },
];
