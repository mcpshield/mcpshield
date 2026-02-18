# Contributing to MCPShield

Thanks for your interest in making the MCP ecosystem safer! Here's how to contribute.

## Reporting Vulnerabilities

The most impactful contribution is reporting new MCP server vulnerabilities.

### How to report

1. Open an issue with the `vulnerability-report` label
2. Include:
   - **Package name** (e.g., `mcp-server-example`)
   - **Vulnerability type** (typosquat, RCE, credential leak, SSRF, etc.)
   - **Severity** (critical/high/medium/low) with CVSS if possible
   - **Description** of the issue
   - **Steps to reproduce** (if applicable)
   - **Affected versions**
   - **Fix available?** (yes/no, with version if yes)

### Responsible disclosure

If the vulnerability is unpatched, please:
- Open an issue with `[RESPONSIBLE DISCLOSURE]` in the title
- Omit exploit details
- We'll coordinate with the package maintainer before publishing full details

## Adding Detection Rules

### New credential patterns

Add to `data/vulndb.js` → `CREDENTIAL_PATTERNS`:

```javascript
{
  pattern: /your-regex-here/i,
  type: "Description of credential type",
  severity: "critical|high|medium|low",
  advice: "How to fix this."
}
```

### New known malicious packages

Add to `data/vulndb.js` → `KNOWN_MALICIOUS`:

```javascript
{
  name: "malicious-package-name",
  impersonates: "legitimate-package-name",
  reason: "Typosquat — description of malicious behavior",
  severity: "critical"
}
```

### New known vulnerabilities

Add to `data/vulndb.js` → `KNOWN_VULNS`:

```javascript
"package-name": {
  package: "package-name",
  verified: true|false,
  vulnerabilities: [{
    id: "CVE-XXXX-XXXXX",
    severity: "critical|high|medium|low",
    cvss: 9.8,
    title: "Short description",
    description: "Full description",
    affected: "<version",
    fixed: "version" | null,
    references: ["https://..."]
  }]
}
```

## Code Contributions

### Setup

```bash
git clone https://github.com/mcpshield/mcpshield.git
cd mcpshield
# No npm install needed — zero dependencies
```

### Running

```bash
# Run against test config
node src/index.js scan --config examples/vulnerable-config.json

# Run with JSON output
node src/index.js scan --config examples/vulnerable-config.json --json
```

### Project Structure

```
src/
├── index.js          # CLI entry point & orchestrator
├── config.js         # Config discovery & parsing
├── typosquat.js      # Typosquat detection engine
├── credentials.js    # Credential & permission scanner
├── cvecheck.js       # CVE database matching
├── registry.js       # npm registry live lookup
└── output.js         # Terminal formatting & reports

data/
└── vulndb.js         # Vulnerability database (THIS IS THE MOST IMPORTANT FILE)
```

### Conventions

- **Zero dependencies** — we don't use npm packages. Keep it that way.
- **Pure Node.js** — ES modules, Node 18+
- **Descriptive findings** — every finding needs: title, detail, severity, and advice
- **Test both configs** — run against `examples/vulnerable-config.json` AND `examples/clean-config.json`

### Pull Request Process

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test against both example configs
5. Open a PR with a clear description of what you changed and why

## Good First Issues

Look for issues labeled `good-first-issue`. These typically include:

- Adding new credential detection patterns
- Adding new known legitimate packages to the allowlist
- Improving error messages
- Adding support for new MCP client config locations
- Documentation improvements

## Code of Conduct

Be kind. Be constructive. We're all here to make AI safer.
