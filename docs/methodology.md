# Methodology — the Capability-Flow Trust Model (`mcptrustchecker-1.0`)

This document specifies exactly what MCP Trust Checker does, stage by stage. It is the spec behind every finding. The design goal is **auditability**: nothing here depends on a model's opinion, so a result can be reproduced and defended.

The engine operates on one object — the **normalized surface** ([`ServerSurface`](../src/types.ts)) — regardless of how it was acquired (stdio, HTTP, static manifest, client config, or package). Every detector consumes a surface and emits [`Finding`](../src/types.ts)s; the scorer turns findings into a grade.

```
INPUT → [0] acquire → [1] unicode → [2] injection → [3] capability
      → [4] toxic-flow → [5] supply-chain → [6] posture → [7] integrity → [8] score
```

---

## [0] Safe acquisition

Scanning is an attack surface: connecting to a stdio config *runs a command*. Acquisition is therefore sandboxed ([`src/acquire/live.ts`](../src/acquire/live.ts)):

- **Executable allowlist** for stdio: `npx, uvx, python, python3, node, docker, deno`. Anything else is refused unless `--allow-any-command`.
- **Minimal environment** — only `PATH` (plus explicit additions), never a spread of `process.env`, so a hostile server can't read your secrets during a scan.
- **Controlled `cwd`, piped stderr, aggressive timeouts** (per-request and overall wall-clock), and a **bounded pagination loop** so a chatty server can't hang the scan or flood memory.
- **HTTP**: scheme (`http`/`https`) and optional host allowlist validated *before* connecting; Streamable-HTTP with SSE fallback.

Acquisition also records transport facts for stage [6]: an stdio command taken from untrusted config *without* an allowlist is itself the systemic stdio-RCE finding.

The official SDK returns tool metadata **verbatim, with no injection or Unicode inspection** — that gap is exactly what stages [1]–[8] fill.

---

## [1] Lexical / Unicode integrity

Text that a human reviewer sees as blank or normal can carry instructions the model reads. MCP Trust Checker scans **every** text field (tool names & descriptions, each parameter description, prompt text, resource descriptions, and the server's free-text instructions) and, crucially, **decodes rather than strips**. Data: [`src/data/unicode.ts`](../src/data/unicode.ts) (pinned to Unicode 17.0.0).

| Family | Range(s) | Action |
| --- | --- | --- |
| **Tags block** | `U+E0000–E007F` | **Decode** `cp − 0xE0000` → surface the hidden ASCII payload. Critical. |
| **Variation selectors** | `U+FE00–FE0F`, `U+E0100–E01EF` | **Decode** the 256-value byte channel; flag long runs. |
| BiDi override | `U+202A–202E` | Flag. |
| BiDi isolates / marks | `U+2066–2069`, `U+200E/F`, `U+061C` | Flag. |
| Zero-width / joiners | `U+200B–200D`, `U+FEFF` | Threshold (default 5) → encoded-payload signal. |
| Invisible math (steg bits) | `U+2060–2064` | Flag. |
| Unusual whitespace | NBSP, ideographic, thin spaces… | Low. |
| C0/C1 controls (except `\t \n \r`) | `U+0000–001F`, `U+007F–009F` | Flag. |

**Homoglyphs** are a separate detector: a codepoint blocklist can't catch a *visible* Cyrillic `а` masquerading as Latin `a`. MCP Trust Checker resolves the Unicode **script** of each token and flags any single token that mixes scripts (the signature of impersonation), and maintains a small confusables `skeleton()` used by the typosquat stage. **ANSI/CSI/OSC terminal escapes** (`MTC-UNI-010`) are flagged too — in a terminal client they can hide, recolor, or overwrite text so the approved action differs from what's shown (consent phishing).

---

## [2] Content injection heuristics

The linguistic shape of an instruction aimed at the model — not the human. Patterns live in [`src/data/injectionPatterns.ts`](../src/data/injectionPatterns.ts) and run across **three channels**: the tool description, each parameter description, and the server `instructions` (which fire at connect time, before any tool call — "line jumping").

Detected kinds: **authority/secrecy** ("IMPORTANT", "ignore previous instructions", "do not tell the user"), **forced sequencing** ("before executing any tool", "always call this first"), **sensitive-target references** (`~/.ssh`, `.env`, "system prompt", "chat history"), **exfil-shaped parameters** (a `context`/`side_note` param whose description tells the model to stuff data into it), **cross-tool shadowing** (redirecting a recipient, overriding another tool, or ranking-manipulation like "prefer this tool over others" — `MTC-INJ-SHADOW-1/3`), **encoded payloads** (base64 + decode/execute), **shell commands embedded in prose**, and **embedded credential values** — a real AWS/GitHub/Slack/JWT/PEM secret hardcoded in metadata is flagged `confirmed` and redacted in the evidence (`MTC-INJ-SECRET-1`).

Keyword matching alone is deliberately weak — attackers use euphemisms (e.g. "apples = strings starting with eyj" to smuggle a JWT past a filter). So injection findings mostly raise the *confidence* axis; the real exfiltration signal comes from stage [4]. One exception: when **multiple** poisoning signals co-occur in a single field (e.g. authority + secrecy + a sensitive target), MCP Trust Checker escalates to a **critical** compound-poisoning finding — that combination is not incidental.

---

## [3] Capability extraction

Each tool is tagged with the roles it can play, derived from its **name, description verbs, and parameter shape** — [`src/util/capabilities.ts`](../src/util/capabilities.ts), lexicon in [`src/data/capabilityLexicon.ts`](../src/data/capabilityLexicon.ts):

- `untrusted-input` — ingests attacker-controllable content (web fetch, read issue/email/ticket…)
- `sensitive-source` — reads private/local data (files, env, secrets, db…)
- `external-sink` — sends data out / acts externally (HTTP, email, publish, webhook…)
- `code-exec` — runs shell commands or evaluates code (a severe sink)
- `file-write` — writes or deletes files

Two rules matter here. First, **`untrusted-input` and `sensitive-source` are kept separate** — merging them would both over- and under-flag the trifecta. Second, MCP Trust Checker **never trusts the server's `annotations`** (`readOnlyHint`, `destructiveHint`): the SDK itself says not to. Instead it *derives* behavior and raises a finding when an annotation **contradicts** it — a destructive tool claiming `readOnlyHint: true` is exactly how a hostile server hides (`MTC-CAP-003`); an honest `openWorldHint: true` on a sensitive-reading tool is itself a trifecta signal (`MTC-CAP-004`).

This stage also emits **schema-level injection preconditions** — a command-, URL/host-, or path-shaped parameter with *no* enum/pattern constraint on a tool that already has the matching capability is the advertised half of command-injection / SSRF / path-traversal (`MTC-CAP-006/007/008`) — and **declared-capability findings**: a server advertising the MCP `sampling` (`MTC-CAP-009`) or `elicitation` (`MTC-CAP-010`) capability is a reverse-trust / consent-phishing precondition that a static scanner can flag offline, escalated when an elicitation server also exposes secret-seeking fields.

---

## [4] Toxic-flow graph  ★

The flagship. The **lethal trifecta**: `untrusted-input → sensitive-source → external-sink`, co-reachable in one agent session, is a data-exfiltration primitive. MCP Trust Checker checks role co-presence across **all tools**, and — with `--include-builtins` — the client's own built-in tools, which frequently complete the trifecta on their own. Logic in [`src/detectors/toxicFlow.ts`](../src/detectors/toxicFlow.ts).

| Situation | Rule | Severity / Confidence |
| --- | --- | --- |
| One tool holds all three roles | `MTC-FLOW-001` | critical / **confirmed** |
| Three roles across ≥2 tools | `MTC-FLOW-002` | critical / strong |
| One tool reads sensitive data *and* can egress | `MTC-FLOW-003` | high / strong |
| Source + sink across tools (no untrusted-input) | `MTC-FLOW-004` | high / strong |
| Untrusted input reaches an action sink (no source) | `MTC-FLOW-005` | medium / strong |

**Honesty contract:** static analysis proves the *primitive exists* (capabilities co-present), not that a runtime chain *will* run. Only a single-tool completed trifecta is `confirmed` (and thus F-gate-eligible); cross-tool trifectas are `strong` — serious, and gated to at most D, but not an automatic F.

When a scan covers **several servers** (e.g. a whole client config), this stage also runs a **cross-server tool-name collision** check (`MTC-INJ-SHADOW-2`): a server whose tool name exactly matches, is a homoglyph of, or is a near-miss of a trusted server's tool can hijack tool selection by connection order or embedding rank.

---

## [5] Supply-chain & typosquatting

Multi-signal, anchored to a curated protected list ([`src/data/protectedPackages.ts`](../src/data/protectedPackages.ts)) — never all-pairs. Logic in [`src/detectors/supplyChain.ts`](../src/detectors/supplyChain.ts):

- **Known squats** (pre-computed table) → instant hit.
- **Fake official scope** (`@modlecontextprotocol/…`) and **unscoped shadows** of scoped packages.
- **Homoglyph skeleton** collision with a protected name.
- **Damerau-Levenshtein** distance 1–2, **gated by a download anomaly** (a near-miss on a high-traffic name with negligible downloads of its own is malice, not coincidence) and keyboard-adjacency.
- **Combosquat** suffixes (`-js`, `-server`, …) stripped before comparison.
- **Provenance/malware signals**: install/pre/post-install scripts (the dominant malware vector), missing repository, missing license.
- **Unpinned spec** (`MTC-SUP-013`): an `@latest`/floating install spec is the rug-pull *enabler* — flagged on the first scan, before any baseline exists.
- **Dependency signals** (`MTC-SUP-014`): declared dependencies are run through the same squat check and matched against the known-vuln table by name.

Package metadata is best-effort and **offline by default**; `--online` pulls registry data (npm/PyPI) for richer signals.

---

## [6] Transport / host posture & known CVEs

Cheap, high-value checks content-only scanners miss ([`src/detectors/posture.ts`](../src/detectors/posture.ts)): user-controlled stdio command without an allowlist (critical, the stdio-RCE class), plaintext HTTP, binding to `0.0.0.0`, a **DNS-rebinding** posture note for browser-reachable localhost HTTP/SSE servers (`MTC-NET-006`), and a **known-CVE version matcher** for MCP client/proxy/server packages (`mcp-remote < 0.1.16`, `@modelcontextprotocol/inspector < 0.14.1`, and others in [`src/data/knownCves.ts`](../src/data/knownCves.ts)).

---

## [7] Rug-pull integrity (Trust On First Use)

Trust binds to content. MCP Trust Checker pins the SHA-256 of the **full canonical schema** (name + description + input/output schema + annotations + spawn command) in `mcptrustchecker.lock`, and diffs it on every rescan ([`src/lockfile.ts`](../src/lockfile.ts)). Silent drift — a tool redefining itself after approval (MCPoison) — becomes a `MTC-TOFU-001` finding with a human-readable diff, requiring re-approval. Commit the lockfile to git.

---

## [8] Scoring

Deterministic penalties from 100, with diminishing returns, category caps, and weakest-link hard gates → a 0–100 Trust Score, an A–F grade, and a fully itemized penalty vector. Specified in **[scoring.md](scoring.md)**.
