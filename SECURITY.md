# Security Policy

## Scope

MCP Trust Checker is a security tool, so two kinds of issues matter:

1. **A vulnerability in MCP Trust Checker itself** — e.g. a way to make the scanner execute untrusted code during acquisition, a ReDoS in a pattern, or a path that leaks environment secrets. Please report these privately.
2. **A detection gap or false result** — a real attack MCP Trust Checker misses, or a benign server it wrongly flags. These are fine to file as public issues and are very welcome.

## Reporting a vulnerability

Please report vulnerabilities in MCP Trust Checker **privately** via GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository (Security → Report a vulnerability), rather than opening a public issue.

Include: affected version, a minimal reproduction (a crafted manifest or config is ideal), and the impact. We aim to acknowledge within a few days.

If Private Vulnerability Reporting is unavailable, email **support@mcptrustchecker.com**.

## Safe-by-default acquisition

Scanning an MCP server is inherently risky — a stdio config can run arbitrary commands. MCP Trust Checker mitigates this by default:

- stdio executables are **allow-listed** (`npx, uvx, python, python3, node, docker, deno`); others are refused without `--allow-any-command`.
- child processes receive a **minimal environment** (never your full `process.env`), a controlled `cwd`, captured stderr, and aggressive timeouts.
- servers found in a client config are **not spawned** unless you pass `--run`.
- HTTP targets are scheme/host-validated before connecting.

Even so: **only scan servers you have some reason to run.** Prefer scanning a static `tools.json` manifest when you just want to inspect metadata.

## Known limitations (threat-model boundaries)

Documented honestly rather than hidden:

- **`--run` against a live HTTP endpoint follows redirects with re-validation** (each hop's host is re-checked by the SSRF guard). SSE fallback relies on the client's `EventSource`; if it does not honor the injected fetch, prefer `--allowed-hosts` to pin the destination.
- **A malicious `--run` server that floods stdout with no newline** can grow parent memory (buffered by the MCP SDK). Connect/request timeouts bound latency, not bytes; scan untrusted stdio servers in a constrained environment.
- **Version-range/`latest` package specs are not evaluated for CVEs** — only a concrete pinned version is matched, to avoid false positives.
- Determinism and the SSRF guard are covered by regression tests; the acquisition sandbox is defense-in-depth, not a substitute for isolating truly hostile servers.

## Supported versions

MCP Trust Checker is pre-1.0. Security fixes land on the latest `0.x` release.
