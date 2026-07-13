# CI integration

MCP Trust Checker is CI-native: SARIF 2.1.0 for GitHub's Security tab, exit codes for gating, and Markdown for PR comments.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | scan completed; gates passed |
| `1` | a gate failed (`--fail-under`, `--min-grade`, or `diff` drift) |
| `2` | usage / runtime error |

```bash
mcptrustchecker scan ./tools.json --min-grade B        # exit 1 if worse than B
mcptrustchecker scan ./tools.json --fail-under 80       # exit 1 if score < 80
mcptrustchecker diff ./tools.json                        # exit 1 if the surface drifted since pin
```

## GitHub Action (bundled)

```yaml
# .github/workflows/mcptrustchecker.yml
name: MCP Trust Checker
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write     # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: illiahaidar/mcptrustchecker@v0
        with:
          target: ./tools.json    # manifest, URL, config, or package
          min-grade: B            # optional gate
          fail-under: '80'        # optional gate
          sarif: true             # upload results to the Security tab
```

See [`action.yml`](../action.yml) for all inputs.

## Raw CLI + SARIF upload

If you prefer to drive it yourself:

```yaml
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx mcptrustchecker scan ./tools.json --sarif -o mcptrustchecker.sarif --min-grade B
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: mcptrustchecker.sarif }
```

## PR comment with the Markdown report

```yaml
      - run: npx mcptrustchecker scan ./tools.json --md -o report.md
      - uses: marocchino/sticky-pull-request-comment@v2
        with: { path: report.md }
```

## Rug-pull gate for a config you depend on

Commit `mcptrustchecker.lock`, then fail the build if any server's surface changed:

```yaml
      - run: npx mcptrustchecker diff ./mcp.config.json     # exit 1 on drift
```

## Trust badge

Emit a shields.io endpoint document and host it (e.g. commit to a `gh-pages` branch or a gist):

```bash
mcptrustchecker scan ./tools.json --badge -o badge.json
```

```markdown
![MCP Trust](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/gh-pages/badge.json)
```
