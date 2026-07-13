/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * MCP Trust Checker core type model.
 *
 * Everything in the engine is expressed against a single normalized, transport-
 * agnostic view of a server — the {@link ServerSurface}. Acquisition adapters
 * (stdio / HTTP / static JSON / client config) all produce a `ServerSurface`;
 * every detector consumes one and emits {@link Finding}s; the scorer turns
 * findings into an auditable {@link Score}. Keeping this model small and pure is
 * what makes the whole tool deterministic and offline-capable.
 */

// ---------------------------------------------------------------------------
// Surface model — the normalized security surface of an MCP server
// ---------------------------------------------------------------------------

/** Where a surface was acquired from (drives which detectors have signal). */
export type SurfaceSourceKind =
  | 'stdio' // spawned a local command and spoke MCP over stdio
  | 'http' // connected to a Streamable-HTTP / SSE endpoint
  | 'manifest' // read a pre-generated tools.json (offline)
  | 'client-config' // extracted from a client config (claude_desktop_config.json, etc.)
  | 'package'; // resolved package metadata only (no live surface)

export interface SurfaceSource {
  kind: SurfaceSourceKind;
  /** Human-readable origin: a path, URL, or package spec. */
  origin: string;
}

/** A JSON-Schema-ish object as advertised by a tool's `inputSchema`. */
export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  required?: string[];
  enum?: unknown[];
  description?: string;
  title?: string;
  format?: string;
  [k: string]: unknown;
}

/**
 * Tool behavior hints as advertised by the server.
 *
 * SECURITY NOTE: these are attacker-controllable and MUST NOT be trusted for
 * security decisions. MCP Trust Checker reads them only to flag when they *contradict*
 * a tool's derived capabilities (annotation-vs-behavior mismatch).
 */
export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  [k: string]: unknown;
}

export interface ToolDef {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: JsonSchema;
  outputSchema?: JsonSchema;
  annotations?: ToolAnnotations;
}

export interface PromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface PromptDef {
  name: string;
  title?: string;
  description?: string;
  arguments?: PromptArgument[];
}

export interface ResourceDef {
  uri?: string;
  uriTemplate?: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

export interface TransportInfo {
  kind: 'stdio' | 'http' | 'sse' | 'unknown';
  /** For HTTP/SSE transports. */
  url?: string;
  /** For stdio transports. */
  command?: string;
  args?: string[];
  /**
   * True when the spawned `command`/`args` originate from untrusted metadata
   * without an executable allowlist — the systemic stdio-RCE class.
   */
  userControlledCommand?: boolean;
  /** Execution-hijacking env vars that were stripped before spawning, if any. */
  droppedEnv?: string[];
}

/** Package/provenance metadata, if the target maps to a known package. */
export interface PackageMeta {
  registry?: 'npm' | 'pypi' | 'unknown';
  name?: string;
  version?: string;
  /** Raw install/lifecycle scripts, if known. */
  scripts?: Record<string, string>;
  dependencies?: string[];
  repositoryUrl?: string | null;
  license?: string | null;
  weeklyDownloads?: number | null;
  /** ISO 8601 publish timestamp of the resolved version, if known. */
  publishedAt?: string | null;
  /** Whether the install spec pins an exact version (false = @latest/floating). */
  pinned?: boolean;
  /** The raw version token from the install spec, if any (e.g. "latest", "^1.2.0"). */
  requestedSpec?: string;
}

/** The single normalized object every detector operates on. */
export interface ServerSurface {
  /** Stable identity used for lockfile pinning (package spec, url, or path). */
  id: string;
  source: SurfaceSource;
  server: {
    name?: string;
    version?: string;
    title?: string;
    /** Free-text server instructions — a first-class line-jumping surface. */
    instructions?: string;
    protocolVersion?: string;
    capabilities?: Record<string, unknown>;
  };
  tools: ToolDef[];
  prompts: PromptDef[];
  resources: ResourceDef[];
  transport?: TransportInfo;
  packageMeta?: PackageMeta;
  /**
   * Server implementation source, when available (a local package directory or
   * an extracted tarball). Enables implementation-level analysis — reading what
   * the code *does*, not only what the tool metadata *claims*.
   */
  sourceFiles?: SourceFile[];
}

export interface SourceFile {
  /** Path relative to the package root. */
  path: string;
  content: string;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * How sure we are — the "severity ≠ risk" split: a heuristic
 * keyword hit and a decoded hidden-instruction payload can share a severity
 * but must not carry the same weight — and only `confirmed` findings can fire
 * a hard grade gate.
 */
export type Confidence = 'confirmed' | 'strong' | 'heuristic' | 'speculative';

export type Category =
  | 'injection' // prompt-injection / tool-poisoning / line-jumping
  | 'exfiltration' // secrets & data-exfiltration (incl. toxic-flow)
  | 'permissions' // over-broad scope / dangerous capabilities
  | 'supply-chain' // typosquat / install scripts / provenance / known CVEs
  | 'network' // transport & host posture
  | 'hygiene'; // metadata / documentation / minor issues

export interface FindingLocation {
  kind: 'tool' | 'prompt' | 'resource' | 'server' | 'package' | 'transport' | 'flow';
  /** Name of the tool/prompt/resource, when applicable. */
  name?: string;
  /** Field within the object, e.g. `description` or `inputSchema.properties.path.description`. */
  field?: string;
}

export interface Finding {
  /** Stable rule id, e.g. `MTC-UNI-001`. Used for docs, baselines and SARIF. */
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** What was found and why it matters. */
  description: string;
  remediation?: string;
  location?: FindingLocation;
  /** Concrete evidence: a decoded payload, matched snippet, offending name, etc. */
  evidence?: string;
  /** External references (OWASP, CVE, blog posts, spec sections). */
  references?: string[];
  /** OWASP MCP Top 10 / LLM Top 10 mapping id, when available. */
  owasp?: string;
  /** Structured extras for machine consumers. */
  data?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Capabilities & toxic flows
// ---------------------------------------------------------------------------

export type CapabilityTag =
  | 'untrusted-input' // ingests attacker-controllable content (web, issues, email…)
  | 'sensitive-source' // reads private/local data (files, env, secrets, db…)
  | 'external-sink' // can send data out / act externally (http, email, publish…)
  | 'code-exec' // runs shell commands or evaluates code (a severe sink)
  | 'file-write'; // writes or deletes files

export interface ToolCapability {
  tool: string;
  tags: CapabilityTag[];
  /** Why each tag was assigned (keyword/schema evidence), for explainability. */
  reasons: Partial<Record<CapabilityTag, string[]>>;
}

/** How much a server could do if the model driving it were manipulated. */
export type CapabilityLevel = 'minimal' | 'moderate' | 'high' | 'critical';

export interface CapabilityProfile {
  level: CapabilityLevel;
  /** Human-readable reasons the level was assigned. */
  reasons: string[];
  /** The union of capability tags observed across the server's tools. */
  tags: CapabilityTag[];
}

export interface ToxicFlow {
  id: string;
  severity: Severity;
  confidence: Confidence;
  /** Tool(s) that supply the untrusted input, if any. */
  untrustedInput: string[];
  /** Tool(s) that read sensitive data, if any. */
  sensitiveSource: string[];
  /** Tool(s) that can exfiltrate / act externally. */
  externalSink: string[];
  /** True when a single tool holds more than one role (self-contained primitive). */
  selfContained: boolean;
  /** The concrete attack chain of tools (e.g. ["fetch_url","read_file","http_request"]). */
  path?: string[];
  /** True when at least one leg of the path is a direct schema wire (higher plausibility). */
  pathWired?: boolean;
  description: string;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScoreVectorItem {
  ruleId: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** Base weight for the severity. */
  rawWeight: number;
  confidenceMult: number;
  /** Diminishing-returns multiplier for the Nth finding of this rule. */
  diminishingFactor: number;
  /** rawWeight × confidenceMult × diminishingFactor, rounded to 2dp. */
  appliedPenalty: number;
}

export interface Score {
  /** 0–100, higher is safer. */
  score: number;
  /** Final grade after gates. */
  grade: Grade;
  /** Grade implied by the raw number, before hard gates. */
  band: Grade;
  /** Strictest grade cap forced by a hard gate, if any. */
  gateCap?: Grade;
  /** Points subtracted per category (after per-category caps). */
  categorySubtotals: Record<Category, number>;
  /** Fully itemized, reconstructable penalty vector. */
  vector: ScoreVectorItem[];
  /** Human-readable descriptions of every gate that fired. */
  gatesFired: string[];
  methodologyVersion: string;
}

// ---------------------------------------------------------------------------
// Integrity (rug-pull / TOFU)
// ---------------------------------------------------------------------------

export type IntegrityStatus = 'first-seen' | 'unchanged' | 'drift';

export interface SurfaceChange {
  kind: 'tool-added' | 'tool-removed' | 'tool-changed' | 'instructions-changed';
  name?: string;
  detail: string;
}

export interface IntegrityResult {
  status: IntegrityStatus;
  currentDigest: string;
  previousDigest?: string;
  /** Populated when status is `drift`. */
  changes?: SurfaceChange[];
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export interface ScanReport {
  tool: {
    name: string;
    version: string;
    methodologyVersion: string;
  };
  target: {
    id: string;
    source: SurfaceSource;
    server?: { name?: string; version?: string };
  };
  /** ISO timestamp. Omitted for reproducible (deterministic) reports. */
  scannedAt?: string;
  findings: Finding[];
  score: Score;
  capabilities: ToolCapability[];
  /** The server's blast-radius rating (independent of the trust grade). */
  capabilityProfile: CapabilityProfile;
  toxicFlows: ToxicFlow[];
  integrity?: IntegrityResult;
  /** SHA-256 of the canonicalized surface — the rug-pull fingerprint. */
  surfaceDigest: string;
  stats: {
    tools: number;
    prompts: number;
    resources: number;
    findingsBySeverity: Record<Severity, number>;
  };
}

// ---------------------------------------------------------------------------
// Detector contract
// ---------------------------------------------------------------------------

export interface DetectorContext {
  surface: ServerSurface;
  config: ResolvedConfig;
  /** Per-tool capability tags, computed once by the engine and shared. */
  capabilities: ToolCapability[];
  /**
   * Tool names exposed by OTHER servers in the same scan, for cross-server
   * name-collision / shadowing detection. Empty when scanning a single target.
   */
  siblingTools?: { server: string; name: string }[];
}

export interface Detector {
  id: string;
  /** Pipeline stage number (see docs/architecture.md). */
  stage: number;
  title: string;
  run(ctx: DetectorContext): Finding[] | Promise<Finding[]>;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface McpTrustCheckerConfig {
  /** Rule ids to disable entirely. */
  disabledRules?: string[];
  /** Rule ids whose findings are allowed (suppressed) — an explicit waiver list. */
  allowlist?: string[];
  /** Fail CI when the score is below this threshold (0–100). */
  failUnder?: number;
  /** Fail CI when the grade is worse than this (e.g. "B"). */
  minGrade?: Grade;
  /** Path to the integrity lockfile. */
  lockfile?: string;
  /**
   * When true, the toxic-flow graph assumes the client also exposes generic
   * built-in tools (web-fetch as untrusted input, file/network as sinks), which
   * can complete a trifecta on their own.
   */
  includeBuiltins?: boolean;
  /** Additional package names to hard-protect against typosquatting. */
  protectedPackages?: string[];
  /** Zero-width character count above which a string is treated as an encoded payload. */
  invisibleCharThreshold?: number;
  /**
   * Location-scoped waivers (a baseline). Unlike `allowlist` (which silences a
   * whole rule everywhere), each entry silences a specific finding on a specific
   * tool/field — with a justification that stays in the config for audit.
   * Also loadable from a standalone `.mtcignore` JSON file next to the config.
   */
  suppress?: Suppression[];
  /** Organisational policy the scan is gated against (see {@link Policy}). */
  policy?: Policy;
}

/** A single baseline waiver. `rule` is required; the rest narrow the match. */
export interface Suppression {
  rule: string;
  /** Only suppress on this tool/prompt/resource name (location.name). */
  tool?: string;
  /** Only suppress on this field (location.field). */
  field?: string;
  /** Why the waiver is safe — kept for audit, never affects matching. */
  reason?: string;
}

/** Policy-as-code: declarative rules a server must satisfy, gated in CI. */
export interface Policy {
  /** Fail if the Trust grade is worse than this. */
  minGrade?: Grade;
  /** Fail if the Capability blast-radius exceeds this level. */
  maxCapability?: CapabilityLevel;
  /** Fail if any of these rule ids fired. */
  denyRules?: string[];
  /** Fail if the server exposes any of these capability tags. */
  denyCapabilities?: CapabilityTag[];
}

/** Config with all defaults resolved — what detectors actually see. */
export interface ResolvedConfig extends Required<Omit<McpTrustCheckerConfig, 'minGrade' | 'lockfile' | 'policy'>> {
  minGrade?: Grade;
  lockfile?: string;
  policy?: Policy;
}
