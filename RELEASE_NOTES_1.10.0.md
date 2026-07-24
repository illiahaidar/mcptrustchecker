# v1.10.0 — scan a GitHub repository, and a hardened SSRF guard

Methodology `mcptrustchecker-1.9` — **unchanged**. No weight, rule, gate or grade
band moved, so **every grade this release produces is identical to 1.9.0**. What
changed is *what you can point it at*, plus one hardening fix in the code path
that talks to a network target.

> 🔍 **Also live: the free online scanner — https://mcptrustchecker.com/scan**
> The same deterministic engine in your browser, no signup and no key. Scan an
> npm or PyPI package, a GitHub repository, a live remote endpoint (OAuth
> sign-in supported), a `tools.json` manifest — or paste your whole client
> config (`claude_desktop_config.json`, `.cursor/mcp.json`) and every server in
> it is graded at once. Every result gets a shareable link and a live Trust
> Score badge for your README.

## New: a repository is a target

```bash
mcptrustchecker scan upstash/context7
mcptrustchecker scan https://github.com/modelcontextprotocol/servers
mcptrustchecker scan owner/repo@v1.2.3
```

Plenty of MCP servers are never published to a registry: they are a repo you are
told to clone, or a pre-release you want to read *before* it ships. Those had no
scannable target — a bare `owner/repo` looked like a missing file, and a
github.com URL was treated as a live MCP endpoint and died on content type.

Accepts `owner/repo`, `owner/repo@ref`, https/ssh github.com URLs, `.git`
suffixes and `/tree/<ref>` links. Every other target shape is untouched: a scoped
package, a path and a live URL still take their own branch, pinned by a
regression test.

**Nothing is cloned, written to disk or executed.** The archive is fetched over
https from GitHub's pinned hosts and unpacked **in memory** by the same bounded
reader that handles npm/PyPI artifacts — same size cap, same redirect
re-validation, same zip-slip-safe entry paths, same unpacked-bytes ceiling. No
git binary runs, so no hook can fire.

A repository is **not** a released artifact, and the scan says so rather than
flattering it: the surface is marked `repo`, verification is the `repo` tier
(public, readable source — never `source` or `vendor`, which require publish
provenance), and the archive's own SHA-256 is recorded, because "the default
branch" is only reproducible against the bytes actually read.

`GITHUB_TOKEN` or `--github-token` lifts GitHub's anonymous rate limit. It goes
to `api.github.com` only and never survives a redirect.

## Hardening: DNS rebinding could walk past the SSRF guard

`isBlockedHost()` compared the hostname as a **string**. That catches
`localhost`, `127.0.0.1`, `10.x`, `169.254.169.254` and their IPv6 forms — but a
hostname is not an address. A perfectly ordinary public name whose `A` record
points at loopback sailed straight through.

That mattered most where it was least visible: **OAuth**. Discovery, dynamic
client registration and token endpoints are all chosen by the *target server's
own metadata*, so a hostile server could nominate a host that looks public and
resolves inward.

- New `isBlockedHostResolved()` resolves the name and blocks it when **any**
  returned address is non-routable — a multi-record name is only as safe as its
  worst answer.
- Applied at the `acquireHttp` entry **and on every `guardedFetch` hop**, so it
  covers redirects and every OAuth host, not just the URL you typed.
- Private-range coverage widened: **CGNAT** (`100.64/10`, RFC 6598), **multicast**
  (`224/4`) and **reserved** space (`240/4`, incl. `255.255.255.255`).
  `100.63.x` and `100.128.x` stay routable.
- `--allowed-hosts` now **wins** over the private-host guard. It ran
  independently, so naming a host explicitly still got it refused — with an error
  telling you to pass the flag you had already passed. Newly important because
  `100.64/10` is Tailscale's range.
- The guard's DNS lookup is **time-boxed (3s)**. `dns.lookup` takes no timeout and
  the entry-point check sits outside the connect budget, so a black-holing
  nameserver could have stalled a scan for tens of seconds.

### Limits, stated plainly

Two behaviours are deliberate, not oversights:

- **An unresolvable name is not treated as blocked.** The connection fails on its
  own, and failing closed would break split-horizon DNS and reject good targets
  on a transient resolver hiccup.
- **A sub-TTL rebind between the lookup and the socket connect remains possible.**
  Pinning the resolved address into the connection is the only complete fix and
  needs a custom dispatcher. This check plus the per-hop re-validation is the
  practical guard, and the code says so.

## Who should upgrade

Everyone: the repository target is additive and nothing about existing results
changes. The hardening matters most if you scan live endpoints, use `--login`, or
run the scanner as a service that accepts a target from someone else.

## Verification

415 tests pass. New blocks pin the repository parser (including the negative
cases that must fall through to other target shapes) and the resolved host guard,
the latter with an **injected resolver** so the suite asserts offline instead of
depending on a third-party domain.

```
npm i -g mcptrustchecker@1.10.0
mcptrustchecker --version     # 1.10.0 (methodology mcptrustchecker-1.9)
mcptrustchecker scan upstash/context7
```

**Full changelog:** https://github.com/illiahaidar/mcptrustchecker/blob/main/CHANGELOG.md
