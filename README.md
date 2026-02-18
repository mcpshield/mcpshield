# ⛨ MCPShield

**MCP Supply Chain Security Scanner** — detect vulnerabilities, typosquats, and misconfigurations in your MCP server configs before they reach production.

Think "Snyk for MCP servers."

## What It Does

MCPShield scans your MCP configuration files (Claude Desktop, Cursor, VS Code, etc.) and detects:

- **Typosquat packages** — Levenshtein distance analysis against 40+ known legitimate MCP packages, plus a database of confirmed malicious packages
- **Known CVEs** — checks every server against a vulnerability database of disclosed MCP security issues (CVE-2025-68145, etc.)
- **Hardcoded credentials** — API keys, database URLs, tokens, private keys embedded in config files
- **Dangerous permissions** — system directory access, disabled sandboxes, unrestricted file access
- **Unverified publishers** — flags packages not from trusted scopes (@anthropic/, @modelcontextprotocol/, etc.)
- **Transport security** — HTTP endpoints, missing authentication on SSE connections

## Quick Start

```bash
# Scan a specific config file
node src/index.js scan --config path/to/claude_desktop_config.json

# Auto-discover and scan all MCP configs on your system
node src/index.js scan

# Output JSON for CI/CD pipelines
node src/index.js scan --config mcp.json --json

# Save report to file
node src/index.js scan --config mcp.json --json --output report.json
```

## Install Globally (optional)

```bash
npm link
mcpshield scan
```

## CI/CD Integration

MCPShield uses exit codes for pipeline integration:

| Exit Code | Meaning |
|-----------|---------|
| 0 | No high/critical findings — safe to proceed |
| 1 | High-severity findings detected |
| 2 | Critical findings (typosquats, RCE, credential exposure) |

### GitHub Actions Example

```yaml
- name: MCP Security Scan
  run: |
    npx mcpshield scan --config .cursor/mcp.json --json --output mcpshield-report.json
  continue-on-error: false

- name: Upload Security Report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: mcpshield-report
    path: mcpshield-report.json
```

## Config File Locations

MCPShield auto-discovers configs from:

| Client | Location |
|--------|----------|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%/Claude/claude_desktop_config.json` |
| Claude Desktop (Linux) | `~/.config/claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` or `.cursor/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |
| VS Code | `.vscode/mcp.json` |
| Continue | `~/.continue/config.json` |

## Example Output

```
  ╔═══════════════════════════════════════════╗
  ║                                           ║
  ║   ⛨  MCPShield v0.1.0                     ║
  ║   MCP Supply Chain Security Scanner        ║
  ║                                           ║
  ╚═══════════════════════════════════════════╝

─── SCANNING: User-specified ──────────────────────────

📦 github (mcp-servr-github)
  🛑 MALICIOUS PACKAGE DETECTED
  Typosquat — contains credential-harvesting payload
  Impersonates: mcp-server-github (distance: 1)
  ↳ REMOVE THIS SERVER IMMEDIATELY

   1.  CRITICAL  MALICIOUS: Typosquat — contains credential-harvesting payload
      Confidence: confirmed | Distance: 1 | Method: single character difference
      ↳ Remove this server and replace with the legitimate package.

─── SCAN SUMMARY ──────────────────────────────────────

  Servers scanned:  8
  Total findings:   18

   CRITICAL   7 findings
   HIGH       6 findings
   MEDIUM     5 findings

  ⛨ 1 typosquat(s) detected — immediate action required
  ⚠ 3 server(s) from unverified publishers
```

## Try It

Test with the included vulnerable config:

```bash
node src/index.js scan --config examples/vulnerable-config.json
```

Test with a clean config:

```bash
node src/index.js scan --config examples/clean-config.json
```

## Architecture

```
mcpshield-cli/
├── src/
│   ├── index.js          # CLI entry point & orchestrator
│   ├── config.js         # Config discovery & parsing
│   ├── typosquat.js      # Typosquat detection (Levenshtein + known malicious DB)
│   ├── credentials.js    # Credential & permission scanning
│   ├── cvecheck.js       # CVE database matching
│   └── output.js         # Terminal formatting & report generation
├── data/
│   └── vulndb.js         # Vulnerability database, known packages, credential patterns
├── examples/
│   ├── vulnerable-config.json    # Test config with intentional issues
│   └── clean-config.json         # Clean config for comparison
└── package.json
```

## Roadmap

- [ ] npm registry live lookup (verify package exists, check download counts)
- [ ] Real-time CVE feed integration (NVD, GitHub Advisory Database)
- [ ] MCP server runtime behavioral analysis
- [ ] Config file watcher (continuous monitoring)
- [ ] VS Code extension
- [ ] GitHub App for PR checks
- [ ] Policy-as-code engine (OPA/Rego)

## License

MIT
