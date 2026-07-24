# Changelog

All notable changes to `mcptrustchecker` are recorded here. The scanner is
deterministic: the **methodology version** is bumped whenever a change could
move a score, so a grade is always reproducible against the version that
produced it.

## 1.9.0 — methodology `mcptrustchecker-1.9`

A full **adequacy audit of every grade** over the live 31,300-package corpus —
checking each band for both *false positives* (benign code graded down) and
*false negatives* (real threats graded up) — found the scanner's remaining error
was concentrated in **which axis one rule fed**, not in its detection. Fixing that
plus eight precision guards moves grades, so **the methodology version moves to
`mcptrustchecker-1.9`**.

### Changed — `MTC-SRC-010` moves to the capability axis (this is what moves grades)

- `eval(value)` / `new Function(value)` is the **same primitive** as `MTC-SRC-001`,
  which has always been capability-only. Evaluating a runtime value is what an
  honest code-runner, interpreter, template engine or notebook tool *does*: it is
  **blast radius, not evidence of malice**. Scoring it as a threat while its
  identical sibling was capability-only double-charged the same capability and was
  the single largest source of unjustified sub-B grades.
- `MTC-SRC-010` still fires, is still reported, and now **raises the capability
  level** (`code-exec`) instead of subtracting from the trust grade.
- **The genuine threat is preserved, not dropped:** the assembled-command **+**
  eval co-presence dropper still scores via `MTC-SRC-011`; decode-then-execute
  droppers stay on `MTC-SRC-004`; untrusted input *reaching* an eval sink remains
  the toxic-flow layer's job (`MTC-FLOW-*`); every hard gate is unchanged.

### Fixed — precision guards (false-positive removal only)

- **`MTC-SRC-004` / `MTC-SRC-007`** now honour the string-literal and comment
  guards, so a security scanner that catalogues these shapes as *data* no longer
  flags itself. `isInsideStringLiteral` was rewritten as a small multi-line lexer
  that tracks `'`/`"` strings (with escapes), **Python triple-quotes** and **JS
  template literals across lines**, and skips `//` and `/* */` so a quote inside a
  comment cannot throw off string parity.
- **`MTC-SRC-004`** exec sinks are **call-anchored** (`eval\s*\(`, `Function\s*\(`,
  `exec\s*\(`): a decoded blob followed by the *word* `evaluate` is no longer a
  decode-and-execute dropper. The canonical `eval(atob(…))` form is untouched.
- **`MTC-UNI-009`** tokenizes on **letter runs** instead of whitespace, so a
  bilingual compound (`MCP-сервер`, `voximplant_клиент`) is two single-script runs
  rather than one "mixed-script" token. A contiguous homoglyph (`pаypal`) still fires.
- **`MTC-SRC-008`** placeholder detection covers `-HERE`/`YOUR-…-KEY` forms and
  letter-digit filler bodies, and a secret is downgraded when the file is a
  **corroborated fixture** (three or more distinct secret shapes, or a
  `leak`/`gitleaks`/`fixture` marker). A lone real credential still gates.
- **`MTC-INJ-CMD-1`**: the self-documenting-tool guard is underscore-aware, so a
  tool named `adb_rm` is recognised as a delete tool documenting itself — while
  `transform`/`confirm`/`alarm` still never match.
- **`MTC-SRC-009`** no longer treats a `RegExp`-literal / `RegExp`-named receiver
  or a GraphQL/Cypher statement as a shell sink; a hard allowlist keeps every
  `child_process` alias (`cp.exec`, `child_process_1.execSync`) firing, and ssh2's
  `conn.exec(cmd)` is deliberately still a shell sink.
- **Non-runtime paths**: `tools` no longer matches at *any* depth. MCP servers
  implement their runtime request handlers in `src/tools` / `dist/tools`, so the
  old token silenced real findings in the server's own code; only a **repo-root**
  `tools/` is treated as maintainer tooling now. AWS's documented example-key
  roots are recognised as placeholders, so honeypot bait is not reported as a leak.

### Also included — the low-grade precision overhaul (landed after the 1.8.0 tag)

Upgrading from `1.8.0` also brings the precision pass that followed it: an audit of
every C/D/F server found the low band was dominated by lexical false positives.

- **`MTC-SRC-008`** (the engine's only `confirmed` rule, and therefore the only
  driver of the confirmed-high gate) no longer "confirms" on documentation
  placeholders (AWS's own example keys, the jwt.io sample token, `xoxb-test-token`),
  on **public-by-design** keys (Supabase `role:anon` JWTs, Firebase/web API keys) or
  on test/example/vendored paths. Only a genuine private credential in runtime code
  keeps `confirmed` — and keeps gating.
- **`MTC-SRC-004`** dropped its two standalone data-literal arms (`\x`-escape runs
  and `String.fromCharCode` lists). A byte table with no decoder and no exec sink —
  indentation, an ASCII alphabet, a codepage table, a binary test fixture — is data,
  not a payload. The four decode-and-execute arms are unchanged.
- **`MTC-SRC-010`** gained the receiver/quote guard `MTC-SRC-001` already had, so
  `page.$eval`, `redis.eval(luaScript)`, `self.eval`, `globalThis.eval` and
  quote-prefixed text no longer read as dynamic evaluation, plus a vendored-idiom
  allowlist (wasm-bindgen glue, empty/escaped `new Function`).
- **`MTC-SRC-009`** recognises a database `.exec()` by receiver *and* by statement
  keyword (`SAVEPOINT`/`RELEASE`/`DETACH`/`ANALYZE`/`REINDEX`, escape-tolerant so a
  minified `db.exec("\nPRAGMA …")` still reads as SQL).
- **`MTC-SRC-006`** narrowed to real key material and real environment
  *serialization*: bare `~/.ssh` (which matched `.ssh/config` and security-tool
  blocklists) and the benign `dict(os.environ)` copy-before-subprocess idiom no
  longer qualify.
- **`MTC-SUP-010`** only escalates to "downloads and runs a remote binary" when the
  install body contains **both** a fetch and an execute-of-the-fetched-artifact,
  tested against the script's code with string literals blanked — so a
  `console.log` banner that merely prints a URL is not a dropper.
- **`MTC-SRC-011`** now names the concrete files its two halves came from, so a
  co-presence claim is auditable rather than a generic accusation.

### Unchanged — deliberately

- The **capability/threat separation**, all severity weights, confidence
  multipliers, category caps, grade bands and the hard-gate ladder
  (confirmed-critical → F, any critical → D, confirmed-high → D/C).
- **`MTC-FLOW-002` stays capability-only.** It is cross-tool *by construction*;
  the single-tool "lethal trifecta" is `MTC-FLOW-001`, which is
  confirmed/critical and already hard-gates to F — so no additional gate is
  warranted and none was added.

## 1.8.0 — methodology `mcptrustchecker-1.8`

This release turns the scanner from an advanced npm auditor into a real
**MCP-threat** scanner, and makes the Trust Score an explicit
**client-adoption-risk** score. Everything runs inside the **one engine**, so the
offline CLI, the registry and the hosted API produce an identical score and
findings for identical input. **The methodology version moves to
`mcptrustchecker-1.8` because grades move.**

### Added — static tool extraction (the MCP-specific detectors finally fire)

- A package scan never spawns the server, so `tools` was empty and the
  MCP-specific detectors — **tool poisoning** (prompt injection in a tool's
  description/params), **hidden-Unicode smuggling**, **cross-tool toxic flows**
  (the lethal trifecta), tool-name **collisions** and **per-tool capability** —
  had nothing to inspect. The new **static tool extractor** (`src/acquire/
  toolExtract.ts`) reconstructs the tool surface from the published source
  (JS/TS `registerTool`/`.tool`/`ListTools` handlers, incl. same-file `const`
  resolution; Python FastMCP `@mcp.tool` and low-level `Tool(...)`), so those
  detectors now run on npm/PyPI packages.
- **Conservative by design — biased to MISS, never to mis-attribute.** Only
  recognised SDK call shapes are read; test/example/fixture files are skipped;
  anything ambiguous is dropped (a missed tool leaves the scan where it was, a
  mis-attributed one would be worse). The surface is marked `toolProvenance:
  'static'`, and a coverage caveat states how many tools were recovered.
- **Confidence guard.** A finding derived from a statically-inferred tool is
  capped below `confirmed`, so a parse slip can never trigger the
  confirmed-critical **F-gate** — a live scan (`--command`) is what escalates a
  real tool-poisoning to F.

### Changed — the score evolves the threat score with three itemized terms

- The capability/threat separation is **unchanged**: the threat machinery
  (severity × confidence × diminishing, per-category caps, the confirmed-critical
  F-gate) is byte-identical. Three small, **subtract-only** client-adoption-risk
  terms now evolve the threat score into the client score:
  - **Capability exposure** `E_cap` — the client's blast radius: `minimal 0 ·
    moderate 3 · high 6 · critical 10`.
  - **Verification discount** `E_ver` — how verifiable the source is: `vendor 0 ·
    provenance (source) 0 · public repo 1 · none 5`; skipped when verification is
    `unknown` (offline).
  - **Coverage honesty** `E_cov` — inspection depth: `live 0 · source 0 · manifest
    4 · metadata 8 · empty 10`.
- `ClientScore = clamp(0..100, round(ThreatScore − E_cap − E_ver − E_cov))`, and
  `grade = stricter(band(ClientScore), threatGateCap)` — **the F-gate is never
  softened**, and the score can never *rise* above the threat score. Each term is
  **one itemized line** in `score.vector` (`kind: 'client'`) and the pure
  `threatScore` is preserved as a sub-field — no black box.

### Changed — injection precision (a per-rule false-positive audit)

- A precision audit found the single-token injection patterns fired almost
  entirely on legitimate documentation. They no longer accuse on their own:
  bare emphasis (`IMPORTANT`), ALL-CAPS acronyms/hardware IDs, doc section
  headers, self-ordering prerequisites (`resolve the id first`) and comparative
  self-preference now only **corroborate** the compound tool-poisoning rule.
- **Mention-vs-use** disambiguation: an override/command/credential-path phrase
  quoted inside a detector/guard tool, or behind a "do not obey" caveat, is
  documented — not planted — so it is downgraded unless corroborated. The
  `Ignore previous instructions` override rule (the only real criticals) is kept.
- **Capability tags** were tightened so toxic-flow analysis stops firing on
  read-only getters (`get_*`/`list_*` are never an egress sink), web-fetch URL
  params (a `fetch(url)` reads, it does not egress) and local file-move
  `destination` paths.
- **Implementation-level (MTC-SRC) precision**: the `Function("m","return
  import(m)")` optional-dependency loader is recognised as a dynamic import, not a
  HIGH "dynamic code execution" (the import is still reported once, at medium); and
  a capability sink (exec/shell/dynamic-load) found in packaging/dev/install
  tooling (`scripts/`, `tools/`, …) is right-sized to a low note "in packaging/dev
  tooling" instead of overstated as a HIGH threat "in server code" — an install
  script's shell is already surfaced by `MTC-SUP-010`.
- **Full-population precision hardening** (a 26-agent audit re-ran the engine over
  the real corpus and measured every grade-B driver). Fixes, all with regression
  tests: MTC-SRC-002/001 receiver-guarded so a bundled `$exec(/re/)` /
  `.eval(` / benign vendored `Function` idiom (get-intrinsic, function-bind,
  global-this/zod probes) is no longer command-exec; `.d.ts` declaration files and
  comment/JSDoc lines never match; `db.exec(\`SELECT …\`)` is a database call, not
  MTC-SRC-009 command injection; MTC-SRC-007 no longer flags the SAFE js-yaml v4
  `yaml.load()`; capability tags for code-exec/file-write require OPERATIVE (name/
  param) evidence, not prose; a `path` param no longer fabricates a sensitive-source
  read (collapsing spurious toxic flows); a tooling-downgraded finding no longer
  inflates the capability level (the downgrade was cosmetic); CRITICAL blast radius
  now requires a real linkage, not mere co-occurrence; MTC-SUP-006 combosquat no
  longer fires on idiomatic `@vendor/mcp-server` names; MTC-SUP-010 severity is by
  script CONTENT (a piped remote dropper is high, `npm rebuild` is low); MTC-SUP-011
  is unscored once verification was checked (no double-charge); `verification=none`
  is coverage-aware (−2 when the source was fully read, −5 only when it was not);
  and the per-file source cap rose 512 KB → 4 MB so bundled single-file `dist`
  builds are analysed instead of dropped to metadata coverage. Net effect: many
  genuine A packages previously mislabelled B are graded correctly.

### Added — verification as an engine signal (with a `repo` tier)

- Publisher classification (npm/PyPI build provenance via Sigstore/SLSA + vendor
  scopes) is computed **inside the engine** on an `--online` scan and stored on
  the report (`packageMeta.verification` / `publisher` / `vendor`).
- A new **`repo`** tier sits between provenance and nothing: a package with a
  public, inspectable repository but no provenance is the ecosystem norm and is
  discounted only lightly (−1), distinct from a package whose source cannot be
  located at all (−5). The repository is resolved robustly from the registry
  document — npm `repository`, else a `homepage`/`bugs` URL on a known code
  forge; PyPI `project_urls`/`home_page` — so packages that omit `repository`
  (e.g. `@anthropic-ai/claude-code`) are not falsely flagged "no source".
- **Offline scans cannot check provenance**, so verification is a distinct
  `unknown`: the term is **skipped** and a coverage caveat records the omission.

### Changed — reports

- The terminal and Markdown reports gained a **client-adoption-risk** breakdown
  (threat score → each term → client score).

## 1.6.0 — methodology `mcptrustchecker-1.4`

The methodology version is unchanged: nothing here can move a score.

### Added — the `publish` command

- **`mcptrustchecker publish <package>`** scans a package and submits it to the
  public [MCP Trust Registry](https://mcptrustchecker.com/registry). It is a
  **separate command on purpose**: `scan` never publishes, never asks, and does
  not change behaviour when an API key happens to be in the environment. Running
  `publish` is itself the consent, so there is no prompt to dismiss.
- **What is sent is an application, never a verdict.** The request carries the
  package identity plus explicit consent — no report, no findings, no source,
  nothing about the machine or its client configs. mcptrustchecker.com re-scans
  the package with its own copy of this engine and publishes *that* result. The
  locally computed grade travels as `localGrade` for comparison only and can
  never become the listed grade, so holding an API key cannot publish "grade A"
  for a malicious package.
- Only **npm and PyPI** packages can be submitted for now. A target with no
  registry identity is refused with an explanation rather than skipped silently,
  and a missing key fails before the package is downloaded.
- `publish` implies `--online`: submitting a package graded from its name alone
  would be worse than not grading it at all.
- **`--token`** (also `MCPTRUSTCHECKER_TOKEN`), **`--category`** and
  **`--publish-url`** (also `MCPTRUSTCHECKER_PUBLISH_URL`) configure it, resolved
  flag → environment → config file. There is deliberately **no config key that
  enables publishing** — a config file you inherited must not be able to submit
  your packages.
- The GitHub Action no longer publishes on its own when a token secret exists.
  Publishing from CI is now an explicit step that runs the command.


## 1.5.0 — methodology `mcptrustchecker-1.4`

This release corrects a systematic bias in the Trust grade: legitimate,
powerful servers — official platform SDKs, browser drivers, cloud connectors —
were graded harshly for merely *containing* a dangerous sink, when the sink is
what such a server is built to do. The fix sharpens the line between "powerful"
(capability, never a penalty) and "negligent/malicious" (a scored threat).

### Changed — scoring model

- **Presence of a sink is capability, not a threat.** Calling `child_process`,
  `exec`, `eval`, a hardcoded egress endpoint, or reading a cloud CLI's
  credential store (`MTC-SRC-001/002/003/005/006`) now raises the **Capability
  level** and never lowers the grade. A browser driver that spawns processes,
  or a cloud SDK that reads its own credential file, is high-capability — not
  distrusted.
- **`MTC-SUP-013` (unpinned version) is advisory only** and is no longer raised
  for a bare scan-by-name, which is unpinned by construction. It previously fired
  on essentially every package and told the reader nothing about that package.
- **`MTC-SUP-012` (no license) is advisory only** — a legal/reuse matter, not a
  security defect, and no longer influences the grade.
- **`MTC-SRC-007` (unsafe deserialization)** lowered from high to medium: its
  presence cannot show that the deserialized data is attacker-reachable.
- **`MTC-SRC-009` (command built from concatenation/interpolation)** is medium,
  not high — a genuine injection *precondition*, but not proof of a reachable
  flow, and most MCP servers are CLI wrappers that interpolate their own
  constants.

### Added — scoring model

- **`MTC-SRC-009` / `MTC-SRC-010`** — threat rules that fire on the actual
  injection *flow* rather than the mere presence of a sink: a command assembled
  from concatenation/interpolation, and `eval`/`new Function` applied to a
  runtime value rather than a fixed literal. This keeps real command injection
  and dynamic-eval droppers detectable while the presence rules move to
  capability.
- **`MTC-SRC-011`** — compound rule: a server that *both* assembles shell
  commands from runtime values *and* evaluates runtime values as code. Each is a
  separate execution primitive; together, in runtime code, they are the dropper
  shape and are scored on top of their parts.
- **Non-runtime path exclusion.** The threat rules `MTC-SRC-009/010` no longer
  fire inside test suites, benchmarks, examples, fixtures, release scripts,
  `scripts/`, `docs/` or `.github/` — code that is shipped but never runs when
  the server serves requests. Capability rules still apply everywhere, and
  install-time hooks remain caught by `MTC-SUP-010` regardless of location.

### Fixed

- **`MTC-SRC-002` false positive:** the bare `exec(`/`spawn(` pattern matched
  `RegExp.prototype.exec` (`regex.exec(str)`); it now requires a real process
  call.
- **PEM private-key false positive:** the `-----BEGIN PRIVATE KEY-----` header
  alone is present in redaction filters and secret scanners *by design*. A
  finding now requires an actual base64 key body, so a tool that hunts keys is
  no longer mistaken for one that leaks them.

### Security — dependency tree

- Pinned patched transitives via npm `overrides`: **`fast-uri` ≥ 3.1.4**
  ([GHSA-v2hh-gcrm-f6hx](https://github.com/advisories/GHSA-v2hh-gcrm-f6hx), high —
  reached through `ajv`) and **`@hono/node-server` ≥ 2.0.5**
  ([GHSA-frvp-7c67-39w9](https://github.com/advisories/GHSA-frvp-7c67-39w9)).
  Both arrive through `@modelcontextprotocol/sdk`, whose latest release still
  resolves to the vulnerable ranges, so `npm audit fix` could not resolve them.
  The scanner only ever imports the SDK's *client* modules, so the Hono server
  adapter was never on a reachable code path — but a security tool should not
  ship a tree that its own users' `npm audit` flags. `npm audit` is now clean.

### Notes

- Development builds `1.4.0`–`1.4.2` were deployment-internal and were never
  published; `1.5.0` is the first public release since `1.3.1` and supersedes
  them.
- All 306 tests pass. Same methodology version + same target ⇒ byte-identical
  score.

## 1.3.1

- Report the correct tool version.

## 1.3.0

- Coverage axis: a third honest dimension alongside Trust and Capability.

## 1.2.0

- Deep-scan the published source of npm/PyPI packages.

## 1.1.0

- Scan OAuth-protected and header-authenticated remote MCP servers.

## 1.0.0

- Initial release: a deterministic, offline security scanner for MCP servers.
