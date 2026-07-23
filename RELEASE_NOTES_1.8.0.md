# v1.8.0 — MCP-threat detection on package scans (methodology `mcptrustchecker-1.8`)

Turns the scanner from an advanced npm auditor into a real **MCP-threat** scanner.
One engine — the CLI, the registry and the hosted API give identical results.
**Grades move, so the methodology version is bumped to `mcptrustchecker-1.8`.**

## Static tool extraction — the MCP detectors finally fire

A package scan never runs the server, so tool poisoning, hidden-Unicode
smuggling and cross-tool toxic flows had no tool surface to inspect. The new
extractor reconstructs the tool surface from the **published source** (JS/TS
`registerTool`/`.tool`/`ListTools` incl. same-file `const` resolution; Python
FastMCP `@mcp.tool` and `Tool(...)`), so those detectors now run on npm/PyPI
packages — not just live servers. It is **biased to miss, never to
mis-attribute**: only recognised SDK shapes are read, tests/examples are skipped,
and a finding inferred from a static tool is capped below `confirmed`, so a parse
slip can never trigger the F-gate.

## Client-adoption-risk score

The threat machinery is unchanged; three small, subtract-only, **itemized** terms
evolve it into the client score — *how safe is this to adopt*:

- **Capability exposure** — blast radius: `minimal 0 · moderate 3 · high 6 · critical 10`
- **Verification** — `vendor 0 · provenance 0 · public repo 1 · none 5` (a new
  **`repo`** tier: an inspectable public repository is the norm, discounted only
  lightly; resolved robustly from npm `repository`/`homepage`/`bugs` and PyPI
  `project_urls`, so packages that omit `repository` aren't falsely flagged)
- **Coverage** — inspection depth: `live 0 · source 0 · manifest 4 · metadata 8 · empty 10`

The pure `threatScore` is preserved and every point is one line in `score.vector`.

## Injection precision (per-rule audit)

Single-token patterns (`IMPORTANT`, ALL-CAPS acronyms, section headers,
self-ordering prerequisites, self-preference) no longer accuse on their own — they
only corroborate the compound tool-poisoning rule. Mention-vs-use disambiguation
spares detector/guard tools that merely quote an attack. Capability tags were
tightened so toxic-flow analysis stops firing on read-only getters, web-fetch URL
params and local file-move destinations.

Deterministic, offline, no LLM. Same methodology version + same target ⇒
byte-identical score.
