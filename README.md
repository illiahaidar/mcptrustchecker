<div align="center">

# 🛡️ MCP Trust Checker

### The local-first, deterministic security scanner for MCP servers

**Know whether a Model Context Protocol server is safe *before* you connect it to your data.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-3c873a.svg)](package.json)
[![Methodology](https://img.shields.io/badge/methodology-mcptrustchecker--1.0-6f42c1.svg)](docs/methodology.md)
[![Tests](https://img.shields.io/badge/tests-294%20passing-brightgreen.svg)](test)
[![Rules](https://img.shields.io/badge/rules-78-orange.svg)](docs/rules.md)
[![No account](https://img.shields.io/badge/account-not%20required-brightgreen.svg)](#why-this-is-different)
[![Offline](https://img.shields.io/badge/runs-100%25%20offline-brightgreen.svg)](#why-this-is-different)

<br/>

<img src="docs/hero.svg" alt="MCP Trust Checker terminal output: an MCP server graded D with a detected toxic-flow trifecta" width="720"/>

<br/>

```bash
npx mcptrustchecker                # 🔍 scan every MCP server you already have installed — zero config
```

<sub>· offline · deterministic · no account · OAuth browser login for protected servers · reads the real published npm/PyPI source · <a href="#the-algorithm-the-capability-flow-trust-model">one novel core</a> ·</sub>

</div>

---

## What makes the algorithm unique

The **Capability-Flow Trust Model** (methodology `mcptrustchecker-1.0`) is an **original algorithm designed from scratch for this project** by [Illia Haidar](https://github.com/illiahaidar) — it is not a wrapper around, or derivative of, any existing scanner or methodology. It is named, versioned, fully specified in [docs/methodology.md](docs/methodology.md), and citable via [CITATION.cff](CITATION.cff).

MCP Trust Checker scores an MCP server the way an **attacker** reasons about it — not as a bag of regex hits, but as a **Capability-Flow Trust Model**. Every tool is reduced to the roles it can actually play — *untrusted-input ingress*, *sensitive-data source*, *external / exec sink* — derived from behavior, **never** from the server's own (attacker-controllable) annotations. Those roles are wired into a **cross-tool toxic-flow graph** that hunts the *lethal trifecta*: the moment untrusted content, private data, and an exfiltration path co-exist in one agent session — whether inside a single tool or composed across several tools plus the client's built-ins. That is the exact shape behind real-world MCP data-exfiltration exploits, and MCP Trust Checker proves the primitive exists **statically**, with an honest confidence split so a single-tool completion reads `confirmed` and a cross-tool composition reads `strong` — never overclaiming.

Three more things sit under that graph:

- **It decodes, not strips.** Unicode Tags-block and variation-selector payloads are *recovered and printed back to you as evidence*, so a hidden "read `~/.ssh/id_rsa` and BCC the attacker" becomes visible text instead of a silent flag.
- **It has rug-pull integrity built in.** The canonical surface is hashed and pinned; any post-approval mutation of a tool definition trips a `confirmed` finding with a per-tool diff.
- **Every point of the 0–100 Trust Score is an auditable, deterministic penalty vector** — fixed severity weights, a confidence multiplier, diminishing returns, per-category caps, and weakest-link gates. Fully reconstructable, identical on every run, gameable by no one. **No LLM in the loop, no telemetry, no account.**

> And it is **comprehensive by design**: the full catalog of known MCP attack techniques is covered in one offline pass — no API key, no LLM. [See the full coverage map ↓](#coverage-the-full-catalog-of-mcp-attack-techniques)

**Jump to:** [Why it's different](#why-this-is-different) · [Quick start](#quick-start) · [The algorithm](#the-algorithm-the-capability-flow-trust-model) · [Coverage](#coverage-the-full-catalog-of-mcp-attack-techniques) · [Scoring](#the-trust-score-is-auditable-by-construction) · [Embed as a library](#embed-the-exact-same-engine-marketplaces--platforms) · [CI / GitHub](#ci--github-integration) · [Rules](docs/rules.md)

---

## The one question millions of MCP users can't answer

> **"Is this server safe to give access to my files, my tokens, and my conversations?"**

An MCP server hands an AI assistant a set of *tools*. Those tool descriptions are read by the model, not by you — a perfect place to hide instructions. A single server that can *read a file* and *make an HTTP request* is already a data-exfiltration weapon. And a server can look harmless on day one, then silently redefine its tools after you approve it. MCP Trust Checker turns all of that into a transparent letter grade you can act on.

```
   ╭────────────╮
   │  GRADE  D  │   Trust Score 69/100
   ╰────────────╯   methodology mcptrustchecker-1.0

Toxic flows (untrusted-input → sensitive-source → external-sink)
  [critical] The three trifecta roles are co-present across tools;
             a prompt-injected agent can chain them.
```

---

## Why this is different

MCP Trust Checker's wedge is **accuracy + explainability + privacy**, with one genuinely novel core — the cross-tool toxic-flow graph. Every property below holds together in a single offline binary — no account, no LLM in the loop, no telemetry:

- 🔒 **Offline by default** — no account, token, API key, or hosted service; your data never leaves the machine.
- 🔐 **Scans protected remote servers** — `--login` runs the full **OAuth 2.0 browser sign-in** (discovery → dynamic client registration → PKCE → token), so it can audit auth-gated remote MCP endpoints, not just public ones — something most scanners can't do. (Or pass a static `--header "Authorization: Bearer …"`.) Tokens stay in memory for the scan only.
- 🎯 **Deterministic** — same input ⇒ byte-identical score, on every run and every machine.
- 🕸️ **Cross-tool toxic-flow graph** — proves the lethal trifecta statically, composed across tools, not just within one.
- 🔬 **Reads the code, not just the claim** — it grades what the implementation *does* (eval / shell-spawn / hardcoded egress / credential reads / obfuscated payloads), so a poisoned server can't hide behind honest-looking tool descriptions. Metadata **and** implementation, in one deterministic pass.
- 📥 **Deep-scans the actual published package** — `scan <name> --online` fetches the npm/PyPI artifact, verifies it against the registry-declared hash, and runs the full source-analysis engine on the exact bytes `npx`/`pip` would install — **in memory, without installing or executing anything**. Also scans packed release artifacts directly: `scan ./server.tgz`, `.whl`, `.zip`.
- 🧬 **Byte-level rug-pull detection** — the verified artifact's SHA-256 is pinned in the lockfile; if the *same version* is ever republished with different bytes, the rescan raises a `critical`, `confirmed` finding (`MTC-TOFU-002`) — the attack an unchanged tool surface hides from every metadata-only check.
- 🔎 **Decodes, not strips** — hidden Unicode payloads (Tags block / variation-selector) are recovered and shown as evidence.
- 📌 **Rug-pull integrity** — the full tool surface is hashed and pinned; any post-approval drift trips a `confirmed` finding with a per-tool diff.
- 🧾 **Auditable Trust Score** — every point is a published, reproducible penalty vector.
- ⚙️ **SARIF + GitHub Action + CI gates** — machine-readable output and pass/fail thresholds out of the box.
- 📦 **Embeddable library** — the identical, versioned engine a marketplace can reuse on-site.
- 🪶 **MIT, plain-data rules** — every rule is transparent and contribution-friendly.

---

## Measured accuracy

Most scanners *assert* they have a low false-positive rate. This one **measures** it. A labeled corpus of malicious and benign MCP servers lives in [`benchmark/`](benchmark/); `npm run benchmark` scores it and reports the numbers (and fails CI on a regression):

| Metric | Score |
| --- | :---: |
| Precision | **100%** |
| Recall | **100%** |
| F1 | **100%** |
| False-positive rate | **0%** |

*(64 labeled servers, held-out cases flagged; "concerning" := Trust grade C or worse. Reproduce with `npm run benchmark`.)* The corpus is honest and versioned — it grows with every calibration case, and the CI gate holds precision/recall ≥ 90%.

---

## Install

```bash
npx mcptrustchecker scan ./tools.json      # zero-install
npm i -g mcptrustchecker                    # CLI everywhere
npm i mcptrustchecker                       # embed the engine in your app
```

Requires Node ≥ 20. Live scanning uses the official [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk).

---

## Quick start

**Zero-config — one command, scans everything you have installed:**

```bash
npx mcptrustchecker          # auto-discovers Claude Desktop/Code, Cursor, Windsurf, Continue, VS Code configs
```

**Or point it at anything:**

```bash
mcptrustchecker scan ./tools.json                          # an offline manifest (deterministic)
mcptrustchecker scan ./path/to/mcp-server                  # a local package dir — analyzes the CODE too
mcptrustchecker scan --command "npx -y @some/mcp-server"   # a local stdio server (sandboxed)
mcptrustchecker scan https://mcp.example.com/mcp           # a live HTTP/SSE endpoint
mcptrustchecker scan https://mcp.example.com/mcp --login   # an OAuth-protected endpoint (browser sign-in)
mcptrustchecker scan https://mcp.example.com/mcp --header "Authorization: Bearer <token>"   # static auth
mcptrustchecker scan @modelcontextprotocol/server-filesystem --online   # fetches + verifies + reads the PUBLISHED source
mcptrustchecker scan mcp-server-fetch --online --registry pypi          # same for PyPI (sdist/wheel)
mcptrustchecker scan ./server-1.2.0.tgz                    # a packed release artifact (.tgz/.whl/.zip) — offline
```

**Outputs & CI gates:**

```bash
mcptrustchecker scan ./tools.json --sarif > mcptrustchecker.sarif   # GitHub code scanning
mcptrustchecker scan ./tools.json --md    > report.md        # PR comment
mcptrustchecker scan ./tools.json --json  > report.json      # machine-readable
mcptrustchecker scan ./tools.json --badge > badge.json       # shields.io endpoint
mcptrustchecker scan ./tools.json --fail-under 80            # exit 1 below a threshold
mcptrustchecker scan ./tools.json --min-grade B             # exit 1 below a grade
```

The terminal report is **detailed by default** — every finding prints its full description (**what** the problem is and **why** it matters), the exact location, the offending **evidence**, a **fix**, and its OWASP mapping, grouped most-severe-first. Add `--details` for external references, or `--quiet` for just the grade line.

---

## The algorithm: the Capability-Flow Trust Model

A 9-stage pipeline over a **normalized, transport-agnostic surface** (tools, prompts, resources, server instructions, transport, package metadata). Each stage emits findings; the scorer turns them into an auditable grade.

```
INPUT ─ manifest.json │ live stdio/http │ client config │ package name
  │
  ▼
[0] SAFE ACQUISITION        allow-listed command (bare-name only) · scrubbed env · timeouts · SSRF guard
  ▼
[1] UNICODE INTEGRITY       decode Tags/variation-selector payloads; BiDi; zero-width; homoglyph; ANSI
  ▼
[2] INJECTION HEURISTICS    tool-poisoning · line-jumping · shadowing · secrecy · exfil · embedded secrets
  ▼
[3] CAPABILITY EXTRACTION   tag tools (untrusted-input / sensitive-source / sink / exec / write);
  │                         annotation mismatch; sampling/elicitation; schema injection preconditions
  ▼
[4] TOXIC-FLOW GRAPH  ★     the lethal trifecta across tools AND client built-ins; + name-collision
  ▼
[5] SUPPLY-CHAIN            typosquat/combosquat/homoglyph · install-scripts · provenance · unpinned · deps
  ▼
[6] TRANSPORT POSTURE       stdio-RCE · plaintext HTTP · 0.0.0.0 · DNS-rebinding · known-CVE version matcher
  ▼
[7] RUG-PULL INTEGRITY      SHA-256 pin of the full schema → diff on every rescan
  ▼
[8] SCORING                 deterministic penalties · diminishing returns · category caps · hard gates
  ▼
OUTPUT ─ terminal │ JSON │ SARIF 2.1.0 │ Markdown │ badge
```

**★ The flagship — cross-tool toxic-flow analysis.** The most dangerous MCP failures aren't one bad tool; they're an innocent *combination*. Give an agent (1) exposure to **untrusted content**, (2) access to **sensitive data**, and (3) a way to **communicate externally**, and you have an exfiltration primitive. MCP Trust Checker derives each tool's roles from behavior (not from its self-declared, attacker-controllable `annotations`) and checks whether the three are co-reachable across every tool, every server, and optionally the client's own built-ins (`--include-builtins`). One tool holding all three → **critical, confirmed**; the roles spread across tools → **critical, strong**.

Full depth: **[docs/methodology.md](docs/methodology.md)**.

---

## Coverage: the full catalog of MCP attack techniques

MCP Trust Checker covers the full catalog of known MCP attack techniques in one offline pass — from tool-poisoning and Unicode smuggling to supply-chain risk and cross-tool toxic flows — plus the flow graph, the decoder, the integrity pin, and the auditable score on top. ★ marks a check that goes beyond what static scanners typically catch.

<details>
<summary><b>📋 Full technique → rule coverage map</b> (37 techniques — click to expand)</summary>

<br/>

| Attack / technique | MCP Trust Checker rule(s) |
| --- | --- |
| Tool poisoning (hidden instructions in descriptions) | `MTC-INJ-AUTH-*`, `MTC-INJ-SECRECY-*`, `MTC-INJ-TARGET-*`, `MTC-INJ-POISON` |
| Prompt injection / instruction override | `MTC-INJ-AUTH-2`, `MTC-INJ-SECRECY-1` |
| Line jumping (pre-invocation seeding) | `MTC-INJ-SEQ-1` |
| Tool shadowing via description redirect | `MTC-INJ-SHADOW-1` |
| Cross-**server** tool-name collision / homoglyph name | `MTC-INJ-SHADOW-2` ★ |
| Tool-selection ranking manipulation | `MTC-INJ-SHADOW-3` ★ |
| Invisible-Unicode channels (zero-width/BiDi/Tags/VS) | `MTC-UNI-001..008` (decoded) ★ |
| Homoglyph / mixed-script | `MTC-UNI-009` |
| ANSI terminal-escape deception | `MTC-UNI-010` ★ |
| Encoded-payload smuggling (base64 + decode) | `MTC-INJ-ENC-1/2` |
| Shell/command-injection strings in prose | `MTC-INJ-CMD-1`, `MTC-CAP-001` |
| Command/code-execution capability | `MTC-CAP-001` |
| Filesystem-mutation capability | `MTC-CAP-002` |
| Annotation spoofing (readOnly/destructive lie) | `MTC-CAP-003` |
| openWorldHint + sensitive read (trifecta signal) | `MTC-CAP-004` ★ |
| **Toxic-flow analysis / lethal trifecta** | `MTC-FLOW-001..005` ★ |
| Command-injection sink precondition (schema) | `MTC-CAP-006` ★ |
| SSRF / cloud-metadata sink precondition (schema) | `MTC-CAP-007` ★ |
| Path-traversal precondition (schema) | `MTC-CAP-008` ★ |
| Sampling-capability abuse | `MTC-CAP-009` ★ (static proxy) |
| Elicitation abuse / consent phishing | `MTC-CAP-010` ★ (static proxy) |
| Rug pull / silent tool-definition mutation | `MTC-TOFU-001` + lockfile |
| Unpinned / @latest auto-update (rug-pull enabler) | `MTC-SUP-013` ★ |
| Typosquat / combosquat / homoglyph squat | `MTC-SUP-001..006` |
| Install-script / provenance risk | `MTC-SUP-010/011/012` |
| Dependency squat / advisory match | `MTC-SUP-014` ★ |
| Known-CVE version matching | `MTC-NET-001` |
| stdio-RCE (unallowlisted command) | `MTC-NET-002` + sandboxed acquisition |
| Plaintext HTTP / 0.0.0.0 bind | `MTC-NET-003/004` |
| DNS rebinding on localhost transport | `MTC-NET-006` ★ |
| Embedded credential value in metadata | `MTC-INJ-SECRET-1` ★ |
| Empty/malformed surface ≠ clean | `MTC-META-001` ★ |
| Config discovery across MCP clients | client-config parser + zero-config auto-discovery |
| Malicious URL / exfil endpoint in tool metadata | `MTC-INJ-URL-1` ★ |
| **Implementation-level sinks** — eval / shell-spawn / hardcoded egress / deserialization | `MTC-SRC-001…007` ★ |
| Credential-path read / environment dump in server code | `MTC-SRC-006` ★ |
| Hardcoded secret in the server's source (not just metadata) | `MTC-SRC-008` ★ |
</details>

**Deliberately out of scope** (so the deterministic, offline, no-account promise holds): LLM-as-judge semantic classification, hosted threat-intel, a runtime guardrail *proxy*, live authN/replay/signing probing, and OAuth-endpoint source analysis. Where a runtime-only class has a static proxy — a *declared* sampling/elicitation capability, an *unbounded* URL/command/path parameter — MCP Trust Checker flags the precondition offline instead.

Full list: **[docs/rules.md](docs/rules.md)** · run `mcptrustchecker rules`.

---

## Two axes: Trust (grade) and Capability (blast radius)

A single number can't answer "should I use this server?" — because **"powerful" and "malicious" are different questions.** A web scraper legitimately needs to fetch untrusted pages and act on them; that's a large *blast radius*, not evidence it's a bad actor. So MCP Trust Checker reports two independent things:

- **Trust — the A–F grade.** Driven by *threat* signals: prompt-injection with concealment, embedded secrets, Unicode smuggling, typosquatting, known CVEs, rug-pull drift, annotation lies, a single tool built as an exfiltration primitive. Answers **"any sign this server is malicious or negligent?"**
- **Capability — a level (Minimal → Critical).** Driven by what the server *can do*: code execution, filesystem writes, network egress, the cross-tool toxic-flow surface. Answers **"how much damage if the model driving it is manipulated?"** — a fact to size access against, **not** a mark against the server.

```
firecrawl   Trust B (81/100)   Capability CRITICAL   → trustworthy, but huge blast radius — grant carefully
poisoned    Trust F            Capability HIGH        → actual malice signals — avoid
memory      Trust A (100)      Capability MINIMAL     → safe and low-power
```

This is why MCP Trust Checker doesn't collapse every capable server into "F" (which would make the grade useless). Popularity is never an input — popular packages get compromised — but a legitimate powerful server keeps a high Trust grade while its Capability is surfaced honestly.

## The Trust grade is auditable by construction

```
TrustScore = clamp( 100 − Σ_categories min(CategoryCap, Σ penalty), 0, 100 )
penalty    = severity_weight × confidence_multiplier × diminishing_factor    (threat findings only)
```

| Severity | Weight | | Confidence | × |
| --- | ---: | --- | --- | ---: |
| Critical | 45 | | Confirmed | 1.0 |
| High | 22 | | Strong | 0.7 |
| Medium | 9 | | Heuristic | 0.4 |
| Low | 3 | | Speculative | 0.2 |

- **Diminishing returns** (`1 · ½ · ¼ · …`) so 40 copies of one nit can't tank a server and benign passes can't dilute one critical.
- **Per-category caps** (injection 50, exfiltration 50, permissions 35, supply-chain 30, network 25, hygiene 10).
- **Hard gates** (weakest-link): a **confirmed critical → F**; **any** critical → at most **D**; a confirmed high → at most **C**; two → **D**. Most gates fire only on `confirmed` findings so a guess never forces a cap — but no critical of any confidence can score above D.
- **Bands:** A 90–100 · B 80–89 · C 70–79 · D 60–69 · F 0–59.

Every report ships the full itemized `vector` and `methodologyVersion`. **Same methodology version + same target ⇒ byte-identical score.** Details: **[docs/scoring.md](docs/scoring.md)**.

---

## Embed the exact same engine (marketplaces & platforms)

MCP Trust Checker is a library first. A marketplace can vet every listed server with **the identical, versioned open-source engine** users audit on GitHub — so "we run unique security checks on every MCP server" becomes a *verifiable* claim.

```ts
import { surfaceFromManifest, scanSurface, renderBadge } from 'mcptrustchecker';

const surface = surfaceFromManifest(toolsJson, 'acme/weather-mcp');
const report  = await scanSurface(surface);

report.score.grade;              // 'A' … 'F'
report.score.score;              // 0 … 100
report.score.methodologyVersion; // 'mcptrustchecker-1.0'  ← pin & display this
report.toxicFlows;               // enumerated exfiltration primitives
renderBadge(report);             // shields.io endpoint JSON for a live trust badge
```

`scanSurface` is pure, deterministic, and offline. See **[examples/programmatic.ts](examples/programmatic.ts)**.

---

## Rug-pull protection (Trust On First Use)

```bash
mcptrustchecker pin  ./tools.json    # writes mcptrustchecker.lock — commit it to git
mcptrustchecker diff ./tools.json    # exits non-zero if the surface changed
```

A tool that quietly rewrites its description after you approve it (the MCPoison / rug-pull class) shows up as **drift** with a human-readable diff, and re-approval is required.

---

## CI / GitHub integration

```yaml
# .github/workflows/mcptrustchecker.yml
name: MCP Trust Checker
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: illiahaidar/mcptrustchecker@v0
        with:
          target: ./tools.json
          min-grade: B
          sarif: true          # uploads to the Security tab
```

See **[docs/ci-integration.md](docs/ci-integration.md)** and **[action.yml](action.yml)**.

---

## Safety: scanning is itself an attack surface

Connecting to an MCP config can run arbitrary commands. MCP Trust Checker's acquisition is sandboxed by default:

- stdio commands are **allow-listed by bare name** (`npx, uvx, python, python3, node, docker, deno`) — a **path-qualified** command (e.g. `/tmp/evil/node`) is refused, closing the basename-spoof bypass.
- child env is **scrubbed** of execution-hijacking variables (`NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_*`, `PYTHON*`, `()`-functions) — an allow-listed runtime can't be redirected.
- servers in a client config are **not spawned** unless you pass `--run`; config-derived HTTP targets are **SSRF-guarded** (private/loopback/link-local blocked).
- HTTP targets are scheme/host-validated; responses are size-capped; all connects are timeout-bounded.

---

## Configuration

`mcptrustchecker.config.json` (auto-discovered) overrides any default — see [examples/mcptrustchecker.config.json](examples/mcptrustchecker.config.json). Two adoption features worth calling out:

- **Baseline / suppressions** — waive a specific finding on a specific tool with a justification (`suppress: [{ rule, tool?, field?, reason }]`), or drop a standalone `.mtcignore` JSON array in your repo. Location-scoped waivers keep CI green without silencing a rule everywhere.
- **Policy-as-code** — declare what "acceptable" means once and gate every scan on it: `policy: { minGrade, maxCapability, denyRules, denyCapabilities }`. Violations print and fail the run.

---

## What MCP Trust Checker is *not*

- Not a runtime proxy/firewall — it analyzes the declared surface, it doesn't sit in the request path.
- Static analysis proves a toxic-flow **primitive exists**, not that a chain **will execute**.
- It does not test server-side auth/authorization (noted, not claimed).
- Heuristics have false positives; every finding carries a `confidence`, and grade gates fire only on `confirmed` findings — so a guess never forces a grade. [Report false positives](.github/ISSUE_TEMPLATE/false-positive.md); the rules are open.

---

## Documentation

- **[docs/methodology.md](docs/methodology.md)** — every pipeline stage in depth
- **[docs/scoring.md](docs/scoring.md)** — the scoring model & reproducibility contract
- **[docs/rules.md](docs/rules.md)** — the complete 78-rule catalogue
- **[docs/architecture.md](docs/architecture.md)** — code layout & how to extend
- **[docs/ci-integration.md](docs/ci-integration.md)** — Action, SARIF, baselines
- **[SECURITY.md](SECURITY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)**

---

## Contributing

Issues, rules, and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). New detectors implement one small interface; new threat data is a plain, reviewable data file with a test.

## License

[MIT](LICENSE) © Illia Haidar · [mcptrustchecker.com](https://mcptrustchecker.com) · [support@mcptrustchecker.com](mailto:support@mcptrustchecker.com).

Created and maintained by **[Illia Haidar](https://github.com/illiahaidar)** — author of the Capability-Flow Trust Model.
