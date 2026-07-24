# Methodology — the Capability-Flow Trust Model (`mcptrustchecker-1.9`)

This document specifies exactly what MCP Trust Checker does, stage by stage. It is the spec behind every finding. The design goal is **auditability**: nothing here depends on a model's opinion, so a result can be reproduced and defended.

The engine operates on one object — the **normalized surface** ([`ServerSurface`](../src/types.ts)) — regardless of how it was acquired (stdio, HTTP, static manifest, client config, or package). Every detector consumes a surface and emits [`Finding`](../src/types.ts)s; the scorer turns findings into a grade.

```
INPUT → [0] acquire → [1] unicode → [2] injection → [3] capability → [3b] implementation
      → [4] toxic-flow → [5] supply-chain → [6] posture → [7] integrity → [8] score
```

**Calibrated against a live corpus, not a whiteboard.** Every rule and guard
specified here is validated against a continuously-scanned corpus of **30,000+ real
MCP servers** published on npm and PyPI. Each methodology revision is driven by a
**full-population audit** of that corpus rather than by spot checks: every server in
a grade band is re-examined for *both* failure directions — false positives (benign
code graded down) and false negatives (real threats graded up) — each candidate
change is checked against an explicit list of threats it must not stop catching, and
the entire corpus is re-scanned before the version ships. `mcptrustchecker-1.9` is a
direct product of that loop: an audit of every grade showed that evaluating a runtime
value was being charged as malice, so `MTC-SRC-010` moved to the capability axis.
The corpus grows and the audits keep running, so the model is expected to keep
tightening — which is precisely why every score carries the methodology version that
produced it, and why grades are only comparable within one version.

Two axes run through every stage below and are the single most load-bearing idea in
the model: a finding either describes **capability** (what the server *could* do —
blast radius) or a **trust threat** (something suggesting it is malicious or
negligent). Only threats lower the grade; capability raises a separate level. A
browser driver, an SSH connector or a code-runner is *legitimately* powerful —
**capable ≠ malicious** — and grading it F for having a large blast radius would
make the score useless. The authoritative list of capability rules is
[`CAPABILITY_RULES` in `src/scoring/model.ts`](../src/scoring/model.ts).

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

## [3b] Implementation-level source analysis

Stages [1]–[3] read what a server **claims**. This stage reads what its code
**does** — whenever the source is available (a local package directory, an
extracted tarball, or the artifact published to npm/PyPI). Fully deterministic:
no LLM, and the code is never executed. Logic in
[`src/detectors/source.ts`](../src/detectors/source.ts), lexicon in
[`src/data/sourcePatterns.ts`](../src/data/sourcePatterns.ts).

The rules split across the two axes exactly as the model requires:

| Rule | What it finds | Axis |
| --- | --- | --- |
| `MTC-SRC-001` | dynamic code execution present (`eval`, `new Function`, `vm`) | capability |
| `MTC-SRC-002` | shell/process execution present (`child_process`, `subprocess`) | capability |
| `MTC-SRC-003` | hardcoded egress to a fixed external host | capability |
| `MTC-SRC-005` | dynamic module load from a non-literal | capability |
| `MTC-SRC-006` | credential-path read / environment serialization | capability |
| `MTC-SRC-010` | dynamic evaluation of a **non-literal** value | capability |
| `MTC-SRC-004` | decode-**and-execute** of an encoded blob (dropper) | **threat** |
| `MTC-SRC-007` | unsafe deserialization (`pickle.loads`, unsafe YAML) | **threat** |
| `MTC-SRC-008` | a live credential value embedded in shipped code | **threat** |
| `MTC-SRC-009` | untrusted input concatenated into a command sink | **threat** |
| `MTC-SRC-011` | assembled command **and** dynamic eval in one server | **threat** |

**Why `MTC-SRC-010` is capability (changed in `mcptrustchecker-1.9`).** Evaluating a
runtime value is the same primitive as `MTC-SRC-001`, which was always
capability-only — it is what an honest code-runner, interpreter, template engine or
notebook tool *does*. Scoring it as a threat charged the same capability twice.
What still scores is the shape that actually indicates malice: a **decode-then-execute
dropper** (`MTC-SRC-004`), an **assembled command** (`MTC-SRC-009`), the **co-presence
of both execution primitives** (`MTC-SRC-011`), and untrusted input *reaching* the
sink, which is stage [4]'s job.

**Presence vs. flow.** The capability rules fire on the mere presence of a sink;
`MTC-SRC-009`/`-011` fire only when the code visibly builds the sink's argument from
a non-literal. That is what separates `exec('git status')` from `exec('curl ' + input)`.

**Precision doctrine — the source scan is lexical, so every rule is guarded.** A
pattern that matches text nobody executes is not evidence:

- **Non-runtime paths** (tests, fixtures, examples, benchmarks, vendored/bundled
  code, repo-root `scripts/`+`tools/`) do not raise runtime-threat claims, and
  capability sinks found there are downgraded and attributed honestly. Nested
  `src/tools` / `dist/tools` are **not** excused — that is where an MCP server puts
  its real request handlers.
- **Comments and string literals** are skipped for the threat rules, so a security
  scanner that catalogues `exec(`/`eval(`/`pickle.loads` shapes as *data* does not
  flag itself. The string check is a small multi-line lexer (escapes, Python
  triple-quotes, JS template literals).
- **Receiver guards**: `page.$eval`, `redis.eval(luaScript)`, `db.exec("SELECT …")`
  and `RegExp.prototype.exec` are not JavaScript `eval` or a shell.
- **Vendored idioms** (`Function("m","return import(m)")`, wasm-bindgen glue,
  `Function("return this")`) are recognised rather than reported as arbitrary eval.
- **Placeholders** (documented example keys, `YOUR-…-KEY`, filler bodies) and
  **public-by-design** credentials (Supabase `role:anon`, Firebase web keys) are not
  leaked secrets; only a genuine private credential in runtime code is `confirmed`.

**Static tool extraction.** A package scan never runs the server, so the tool surface
would be empty and stages [1]–[4] would have nothing to inspect. The extractor
([`src/acquire/toolExtract.ts`](../src/acquire/toolExtract.ts)) reconstructs it from
the published source (JS/TS `registerTool`/`.tool`/`ListTools`; Python FastMCP
`@mcp.tool`, `Tool(…)`). It is **biased to miss, never to mis-attribute**: only
recognised SDK shapes are read, and any finding derived from a statically-inferred
tool is capped below `confirmed`, so a parse slip can never trigger the F-gate — a
live scan is what escalates that far.

---

## [4] Toxic-flow graph  ★

The flagship. The **lethal trifecta**: `untrusted-input → sensitive-source → external-sink`, co-reachable in one agent session, is a data-exfiltration primitive. MCP Trust Checker checks role co-presence across **all tools**, and — with `--include-builtins` — the client's own built-in tools, which frequently complete the trifecta on their own. Logic in [`src/detectors/toxicFlow.ts`](../src/detectors/toxicFlow.ts).

| Situation | Rule | Severity / Confidence | Axis |
| --- | --- | --- | --- |
| One tool holds all three roles | `MTC-FLOW-001` | critical / **confirmed** | **threat** |
| Three roles across ≥2 tools | `MTC-FLOW-002` | critical / strong | capability |
| One tool reads sensitive data *and* can egress | `MTC-FLOW-003` | high / strong | capability |
| Source + sink across tools (no untrusted-input) | `MTC-FLOW-004` | high / strong | capability |
| Untrusted input reaches an action sink (no source) | `MTC-FLOW-005` | medium / strong | capability |

**Honesty contract:** static analysis proves the *primitive exists* (capabilities co-present), not that a runtime chain *will* run — so only the shape that is a primitive **on its own** is treated as a threat.

- **`MTC-FLOW-001`** — one tool that ingests untrusted input, reads sensitive data *and* egresses is a self-contained exfiltration primitive. It is `confirmed`/critical and therefore **hard-gates the grade to F**.
- **`MTC-FLOW-002`–`005`** are **capability observations**: the roles sit on *different* tools, so completing the chain requires the model to be steered across them. A file server plus a web fetcher plus an uploader is what a capable workspace *is*. These raise the capability level (and with it the client's blast-radius term) but **never gate and never lower the trust grade** — grading them down would re-punish capability as malice and would fire on essentially every honest multi-tool server.

Cross-tool co-presence is therefore reported prominently and priced into capability, **not** into trust. If the roles genuinely collapse into one tool, that is `MTC-FLOW-001` by definition, and the F-gate already covers it.

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
- **Unpinned spec** (`MTC-SUP-013`): an explicit `@latest`/floating install spec is the rug-pull *enabler*. Advisory only, and not raised for a bare scan-by-name (unpinned by construction) — a scored penalty there would fire on essentially every package and say nothing about this one.
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

Deterministic penalties from 100, with diminishing returns per rule, per-category caps, and weakest-link hard gates → a 0–100 score, an A–F grade, and a fully itemized vector. Specified in **[scoring.md](scoring.md)**. Three properties matter for reading a grade:

1. **Capability rules are excluded from the threat set before any penalty or gate is computed.** This is what keeps a legitimately powerful server high-trust; it is not a discount applied afterwards.
2. **The threat score is then evolved into a client-adoption-risk score** by three small, subtract-only, itemized terms — capability blast radius, publisher verification, and inspection coverage. Each is one auditable line in `score.vector`, the pure `threatScore` is preserved alongside, and because every term is ≥ 0 the client score can never rise above the threat score.
3. **Hard gates are weakest-link and confidence-aware**: a `confirmed` critical caps the grade at F, any critical at D, and confirmed high findings at D (≥2) or C (1). All but the any-critical floor require `confirmed`, so a heuristic can never force a cap.

The reproducibility contract is **same methodology version + same target ⇒ identical score**, which is why `score.methodologyVersion` is stamped on every report and bumped whenever a change could move a grade.
