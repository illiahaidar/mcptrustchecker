# Changelog

All notable changes to `mcptrustchecker` are recorded here. The scanner is
deterministic: the **methodology version** is bumped whenever a change could
move a score, so a grade is always reproducible against the version that
produced it.

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
