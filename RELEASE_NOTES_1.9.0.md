# v1.9.0 — Major algorithm accuracy upgrade, audited across 30,000+ scanned MCP servers

Methodology `mcptrustchecker-1.9`.

A full **adequacy audit of every grade** over the live 31,300-package corpus —
checking each band for both *false positives* (benign code graded down) and
*false negatives* (real threats graded up) — found the scanner's remaining error
was concentrated in **which axis one rule fed**, not in its detection. In short:
**capability was being scored as malice.**

Correcting that, plus eight precision guards, is the largest accuracy improvement
since the model was introduced. Across the corpus the sub-B population fell by
roughly three quarters as misgraded but honest servers returned to their true band,
while every genuinely malicious package held its grade and no hard gate, weight,
category cap or grade band changed. Grades move, so **the methodology version is
bumped to `mcptrustchecker-1.9`** and scores remain comparable only within a version.

## Refined against 30,000+ real MCP servers — and still improving

The model is calibrated on a continuously-scanned corpus of **30,000+ MCP servers**
published on npm and PyPI. Each revision comes from a **full-population audit** of
that corpus rather than spot checks: every server in a grade band is re-examined for
*both* failure directions — false positives (benign code graded down) **and** false
negatives (real threats graded up) — each proposed change is measured against an
explicit list of threats it must keep catching, and the whole corpus is re-scanned
before the version ships. This release is a direct product of that loop.

Notably, those audits move **which axis a rule feeds** far more often than they move
a weight — the axis assignment is where a scanner actually goes wrong. `1.9.0` changes
exactly one axis and leaves **every** weight, category cap, grade band and hard gate
untouched.

## The headline: `MTC-SRC-010` is now a capability observation

`eval(value)` / `new Function(value)` is the **same primitive** as `MTC-SRC-001`,
which has always been capability-only. Evaluating a runtime value is what an
honest code-runner, interpreter, template engine or notebook tool *does* — it is
**blast radius, not evidence of malice**. Scoring it as a threat while its
identical sibling was capability-only charged the same capability twice, and was
the single largest source of unjustified sub-B grades.

`MTC-SRC-010` still fires and is still reported; it now raises the **capability
level** (`code-exec`) instead of lowering the trust grade.

**Nothing is lost on the threat side.** The shapes that actually indicate malice
keep scoring exactly as before:

- assembled shell command **+** dynamic eval in the same server → `MTC-SRC-011`
- decode-then-execute droppers (`eval(atob(…))`) → `MTC-SRC-004`
- untrusted input *reaching* an eval sink → the toxic-flow layer (`MTC-FLOW-*`)
- every hard gate (confirmed-critical → F, any critical → D, confirmed-high → D/C)

This is the *capable ≠ malicious* axiom applied consistently: a powerful, honest
server should be **high-capability and high-trust**.

## Precision guards (false-positive removal only)

- **`MTC-SRC-004` / `MTC-SRC-007`** now honour the string-literal and comment
  guards, so a security scanner that catalogues these shapes as *data* no longer
  flags itself. `isInsideStringLiteral` became a small multi-line lexer: `'`/`"`
  strings with escapes, **Python triple-quotes**, **JS template literals across
  lines**, and `//` + `/* */` skipped so a quote inside a comment cannot throw off
  string parity.
- **`MTC-SRC-004`** exec sinks are **call-anchored** — a decoded blob followed by
  the *word* `evaluate` is no longer a dropper. `eval(atob(…))` is untouched.
- **`MTC-UNI-009`** tokenizes on **letter runs**, not whitespace: a bilingual
  compound (`MCP-сервер`, `voximplant_клиент`) is two single-script runs instead of
  one "mixed-script" token. A contiguous homoglyph (`pаypal`) still fires.
- **`MTC-SRC-008`** recognises `-HERE` / `YOUR-…-KEY` / letter-digit filler
  placeholders, and downgrades a secret when the file is a **corroborated fixture**
  (≥3 distinct secret shapes, or a `leak`/`gitleaks`/`fixture` marker). A lone real
  credential still gates.
- **`MTC-INJ-CMD-1`** self-documenting-tool guard is underscore-aware, so `adb_rm`
  is recognised as a delete tool documenting itself — `transform`/`confirm`/`alarm`
  still never match.
- **`MTC-SRC-009`** no longer treats a `RegExp`-literal / `RegExp`-named receiver or
  a GraphQL/Cypher statement as a shell sink. A hard allowlist keeps every
  `child_process` alias firing, and ssh2's `conn.exec(cmd)` deliberately remains a
  shell sink.
- **Non-runtime paths**: `tools` no longer matches at *any* depth. MCP servers put
  their runtime request handlers in `src/tools` / `dist/tools`, so the old token
  silenced real findings **in the server's own code**; only a **repo-root** `tools/`
  is maintainer tooling now. AWS's documented example-key roots are treated as
  placeholders, so honeypot bait is not reported as a live leak.

## Also in this release

- `mcptrustchecker explain <rule>` now states which **axis** a rule feeds, and
  `mcptrustchecker rules` marks capability rules `[capability]` — matching
  `docs/rules.md`.
- **The specification now matches the engine.** `docs/methodology.md` gained the
  implementation-level source-analysis stage it was missing entirely (the whole
  `MTC-SRC-*` family, with each rule's axis), an explicit two-axis framing, a
  description of static tool extraction, and an axis column on the toxic-flow
  table — plus a correction: a cross-tool trifecta does **not** cap the grade
  (only the single-tool `MTC-FLOW-001` does). `docs/scoring.md`'s formula now
  includes the three client-adoption-risk terms (`E_cap` / `E_ver` / `E_cov`)
  that produce the published score, and documents the full reproducibility
  payload. `docs/architecture.md` matches the source tree, and `docs/rules.md`
  is regenerated.

## Also included — the low-grade precision overhaul (landed after the 1.8.0 tag)

Upgrading from `1.8.0` also brings the pass that followed it: an audit of every
C/D/F server found the low band was dominated by lexical false positives.

- **`MTC-SRC-008`** — the engine's only `confirmed` rule, and therefore the only
  driver of the confirmed-high gate — no longer confirms on documentation
  placeholders (AWS's own example keys, the jwt.io sample token), on
  **public-by-design** keys (Supabase `role:anon` JWTs, Firebase web keys), or in
  test/example/vendored paths. A genuine private credential in runtime code still
  gates.
- **`MTC-SRC-004`** dropped its two standalone data-literal arms: a byte table with
  no decoder and no exec sink (indentation, an ASCII alphabet, a codepage table, a
  binary fixture) is data, not a payload. The decode-and-execute arms are unchanged.
- **`MTC-SRC-010`** gained the receiver/quote guard `MTC-SRC-001` already had
  (`page.$eval`, `redis.eval(luaScript)`, `globalThis.eval`, quote-prefixed text)
  plus a vendored-idiom allowlist (wasm-bindgen glue, empty/escaped `new Function`).
- **`MTC-SRC-009`** recognises a database `.exec()` by receiver *and* statement
  keyword, escape-tolerant for minified `db.exec("\nPRAGMA …")`.
- **`MTC-SRC-006`** narrowed to real key material and real environment
  *serialization* — bare `~/.ssh` and the `dict(os.environ)` copy-before-subprocess
  idiom no longer qualify.
- **`MTC-SUP-010`** only escalates to "downloads and runs a remote binary" when the
  install body has **both** a fetch and an execute-of-the-fetched-artifact.
- **`MTC-SRC-011`** names the concrete files its two halves came from.

## Deliberately unchanged

- The capability/threat separation, all severity weights, confidence multipliers,
  category caps, grade bands and the full hard-gate ladder.
- **`MTC-FLOW-002` stays capability-only.** It is cross-tool *by construction*; the
  single-tool "lethal trifecta" is `MTC-FLOW-001`, which is confirmed/critical and
  already hard-gates to F. No additional gate was warranted, and none was added.

## Upgrading

Scores computed under `mcptrustchecker-1.8` and `-1.9` are not comparable —
pin and display `report.score.methodologyVersion` (the reproducibility contract is
*same methodology version + same target ⇒ identical score*). Re-scan anything you
have stored.

```bash
npx mcptrustchecker@latest @scope/some-mcp-server --online
```
