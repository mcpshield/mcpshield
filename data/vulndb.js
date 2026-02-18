// Known MCP server vulnerability database
// Sources: CVE feeds, CoSAI MCP Security Framework, Adversa AI threat research
// Last updated: 2026-02-18

export const KNOWN_VULNS = {
  "@anthropic/mcp-server-git": {
    package: "@anthropic/mcp-server-git",
    verified: true,
    vulnerabilities: [
      {
        id: "CVE-2025-68145",
        severity: "critical",
        cvss: 9.1,
        title: "Path validation bypass via prompt injection",
        description: "Allows path traversal through crafted prompts, enabling access to files outside the repository directory.",
        affected: "<0.6.3",
        fixed: "0.6.3",
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-68145"]
      },
      {
        id: "CVE-2025-68143",
        severity: "high",
        cvss: 7.8,
        title: "Unrestricted git_init enables arbitrary repo creation",
        description: "Attacker can initialize git repositories in arbitrary filesystem locations.",
        affected: "<0.6.3",
        fixed: "0.6.3",
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-68143"]
      },
      {
        id: "CVE-2025-68144",
        severity: "high",
        cvss: 7.5,
        title: "Argument injection in git commands",
        description: "User-controlled input passed unsanitized to git CLI arguments allows arbitrary command execution.",
        affected: "<0.6.3",
        fixed: "0.6.3",
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-68144"]
      }
    ]
  },
  "@modelcontextprotocol/server-filesystem": {
    package: "@modelcontextprotocol/server-filesystem",
    verified: true,
    vulnerabilities: [
      {
        id: "MCP-2026-0012",
        severity: "high",
        cvss: 7.2,
        title: "Symlink traversal bypasses allowed_directories",
        description: "Symbolic links can escape the sandboxed directory tree, allowing read access to sensitive system files.",
        affected: "<0.6.3",
        fixed: "0.6.3",
        references: []
      }
    ]
  },
  "@modelcontextprotocol/server-postgres": {
    package: "@modelcontextprotocol/server-postgres",
    verified: true,
    vulnerabilities: [
      {
        id: "MCP-2026-0019",
        severity: "critical",
        cvss: 9.8,
        title: "SQL injection via tool parameter passthrough",
        description: "User-supplied values are interpolated directly into SQL queries without parameterization.",
        affected: "<0.5.0",
        fixed: null,
        references: []
      }
    ]
  },
  "mcp-server-postgres": {
    package: "mcp-server-postgres",
    verified: false,
    vulnerabilities: [
      {
        id: "MCP-2026-0019",
        severity: "critical",
        cvss: 9.8,
        title: "SQL injection via tool parameter passthrough",
        description: "User-supplied values interpolated directly into SQL queries without parameterization.",
        affected: "*",
        fixed: null,
        references: []
      },
      {
        id: "MCP-2026-0020",
        severity: "critical",
        cvss: 9.2,
        title: "Connection string exposed in tool metadata",
        description: "Database credentials stored in plaintext within the MCP tool description visible to the LLM.",
        affected: "*",
        fixed: null,
        references: []
      },
      {
        id: "MCP-2026-0021",
        severity: "high",
        cvss: 8.1,
        title: "No query allow-listing or scope restriction",
        description: "Agents can execute arbitrary DDL/DML including DROP TABLE and data exfiltration queries.",
        affected: "*",
        fixed: null,
        references: []
      }
    ]
  },
  "@microsoft/markitdown-mcp": {
    package: "@microsoft/markitdown-mcp",
    verified: true,
    vulnerabilities: [
      {
        id: "MCP-2026-0008",
        severity: "medium",
        cvss: 6.1,
        title: "SSRF via crafted document URLs",
        description: "Processing documents with embedded URLs can trigger server-side requests to internal network resources.",
        affected: "<1.2.1",
        fixed: "1.2.1",
        references: []
      }
    ]
  },
  "mcp-server-browser": {
    package: "mcp-server-browser",
    verified: false,
    vulnerabilities: [
      {
        id: "MCP-2026-0030",
        severity: "critical",
        cvss: 9.5,
        title: "Arbitrary JavaScript execution via page navigation",
        description: "Agent can navigate to javascript: URLs, executing code in the browser context.",
        affected: "*",
        fixed: null,
        references: []
      },
      {
        id: "MCP-2026-0031",
        severity: "high",
        cvss: 7.9,
        title: "Cookie exfiltration through response metadata",
        description: "Session cookies from visited pages leak through tool response metadata.",
        affected: "*",
        fixed: null,
        references: []
      }
    ]
  }
};

// Legitimate, well-known MCP server package names
export const KNOWN_LEGITIMATE_PACKAGES = [
  "@anthropic/mcp-server-git",
  "@anthropic/mcp-server-github",
  "@anthropic/mcp-server-slack",
  "@anthropic/mcp-server-memory",
  "@anthropic/mcp-server-puppeteer",
  "@anthropic/mcp-server-brave-search",
  "@anthropic/mcp-server-fetch",
  "@anthropic/mcp-server-everart",
  "@anthropic/mcp-server-sequentialthinking",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-gitlab",
  "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-google-maps",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/server-fetch",
  "@modelcontextprotocol/server-sqlite",
  "@modelcontextprotocol/server-everything",
  "@microsoft/markitdown-mcp",
  "mcp-server-github",
  "mcp-server-stripe",
  "mcp-server-linear",
  "mcp-server-notion",
  "mcp-server-obsidian",
  "mcp-server-postgres",
  "mcp-server-sqlite",
  "mcp-server-docker",
  "mcp-server-kubernetes",
  "mcp-server-aws",
  "mcp-server-gcp",
  "mcp-server-azure",
  "mcp-server-browser",
  "mcp-server-playwright",
  "mcp-server-firecrawl",
  "mcp-server-raygun",
  "mcp-server-sentry",
  "mcp-server-datadog",
  "mcp-server-supabase",
  "mcp-server-prisma",
  "mcp-server-redis",
  "mcp-server-mongodb",
];

// Known malicious packages (typosquats and malware)
export const KNOWN_MALICIOUS = [
  { name: "mcp-servr-github", impersonates: "mcp-server-github", reason: "Typosquat — contains credential-harvesting payload", severity: "critical" },
  { name: "mcp-server-githuh", impersonates: "mcp-server-github", reason: "Typosquat — exfiltrates environment variables on install", severity: "critical" },
  { name: "mcp-server-giithub", impersonates: "mcp-server-github", reason: "Typosquat — obfuscated reverse shell in postinstall", severity: "critical" },
  { name: "@anthropic/mcp-server-glt", impersonates: "@anthropic/mcp-server-git", reason: "Typosquat — reads .git/config and SSH keys", severity: "critical" },
  { name: "mcp-server-postgress", impersonates: "mcp-server-postgres", reason: "Typosquat — intercepts database credentials", severity: "critical" },
  { name: "mcp-server-posgres", impersonates: "mcp-server-postgres", reason: "Typosquat — backdoored fork with data exfiltration", severity: "critical" },
  { name: "mcp-server-firecrawll", impersonates: "mcp-server-firecrawl", reason: "Typosquat — exfiltrates crawled content to C2 server", severity: "critical" },
  { name: "mcp-server-notlon", impersonates: "mcp-server-notion", reason: "Typosquat — steals Notion integration tokens", severity: "critical" },
  { name: "mcp-server-slqite", impersonates: "mcp-server-sqlite", reason: "Typosquat — copies database files to external endpoint", severity: "critical" },
  { name: "mcp-server-browsre", impersonates: "mcp-server-browser", reason: "Typosquat — injects credential-stealing scripts into browsed pages", severity: "critical" },
  { name: "@anthroplc/mcp-server-git", impersonates: "@anthropic/mcp-server-git", reason: "Scope typosquat — impersonates @anthropic scope (l vs i)", severity: "critical" },
  { name: "@anthropic-ai/mcp-server-git", impersonates: "@anthropic/mcp-server-git", reason: "Scope typosquat — fake @anthropic-ai scope", severity: "critical" },
  { name: "@modelcontextprotoco1/server-filesystem", impersonates: "@modelcontextprotocol/server-filesystem", reason: "Scope typosquat — l replaced with 1", severity: "critical" },
];

// Credential patterns to detect in config values
export const CREDENTIAL_PATTERNS = [
  { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@/i, type: "Database credentials", severity: "critical", advice: "Use environment variable references ($ENV_VAR) instead of inline credentials." },
  { pattern: /mysql:\/\/[^:]+:[^@]+@/i, type: "Database credentials", severity: "critical", advice: "Use environment variable references instead of inline credentials." },
  { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i, type: "Database credentials", severity: "critical", advice: "Use environment variable references instead of inline credentials." },
  { pattern: /redis:\/\/:[^@]+@/i, type: "Redis credentials", severity: "high", advice: "Use environment variable references instead of inline credentials." },
  { pattern: /sk-[a-zA-Z0-9]{20,}/i, type: "OpenAI API key", severity: "critical", advice: "API keys should never be in config files. Use environment variables." },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/i, type: "Anthropic API key", severity: "critical", advice: "API keys should never be in config files. Use environment variables." },
  { pattern: /xoxb-[0-9]+-[0-9A-Za-z]+/i, type: "Slack Bot token", severity: "critical", advice: "Use environment variable references instead of inline tokens." },
  { pattern: /xoxp-[0-9]+-[0-9A-Za-z]+/i, type: "Slack User token", severity: "critical", advice: "Use environment variable references instead of inline tokens." },
  { pattern: /ghp_[a-zA-Z0-9]{36}/i, type: "GitHub PAT", severity: "critical", advice: "Use environment variable references instead of inline tokens." },
  { pattern: /gho_[a-zA-Z0-9]{36}/i, type: "GitHub OAuth token", severity: "critical", advice: "Use environment variable references instead of inline tokens." },
  { pattern: /glpat-[a-zA-Z0-9_-]{20}/i, type: "GitLab PAT", severity: "critical", advice: "Use environment variable references instead of inline tokens." },
  { pattern: /AKIA[0-9A-Z]{16}/i, type: "AWS Access Key", severity: "critical", advice: "Use IAM roles or environment variables instead of inline keys." },
  { pattern: /password\s*[:=]\s*[^\s,}{]+/i, type: "Plaintext password", severity: "high", advice: "Never store passwords in configuration files." },
  { pattern: /secret\s*[:=]\s*[^\s,}{]+/i, type: "Plaintext secret", severity: "high", advice: "Never store secrets in configuration files." },
  { pattern: /token\s*[:=]\s*[^\s,}{]+/i, type: "Plaintext token", severity: "medium", advice: "Consider using environment variable references for tokens." },
  { pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/i, type: "Private key", severity: "critical", advice: "Private keys must never be embedded in configuration files." },
];

// Dangerous permission patterns in MCP configs
export const DANGEROUS_PERMISSIONS = [
  { pattern: /--allow-all/i, type: "Unrestricted permissions", severity: "high", advice: "Use granular --allow-read and --allow-write flags instead." },
  { pattern: /(\/|\\)(etc|root|sys|proc)\b/i, type: "System directory access", severity: "high", advice: "Restrict file access to application-specific directories." },
  { pattern: /~\/\.ssh/i, type: "SSH directory access", severity: "critical", advice: "MCP servers should never access SSH keys." },
  { pattern: /~\/\.aws/i, type: "AWS credentials directory access", severity: "critical", advice: "MCP servers should never access AWS credential files." },
  { pattern: /~\/\.gnupg/i, type: "GPG keyring access", severity: "critical", advice: "MCP servers should never access GPG keyrings." },
  { pattern: /~\/\.kube/i, type: "Kubernetes config access", severity: "high", advice: "MCP servers should not access kubeconfig by default." },
  { pattern: /~\/\.docker/i, type: "Docker config access", severity: "high", advice: "MCP servers should not access Docker credentials." },
  { pattern: /~\/\.npmrc/i, type: "npm config access", severity: "high", advice: "npm config may contain auth tokens. Do not expose to MCP servers." },
  { pattern: /~\/\.env/i, type: "Dotenv file access", severity: "high", advice: "Environment files contain secrets. Do not expose to MCP servers." },
  { pattern: /~\/\.git-credentials/i, type: "Git credentials file access", severity: "critical", advice: "Git credential store should never be accessible to MCP servers." },
  { pattern: /~\/\.netrc/i, type: "Netrc file access", severity: "critical", advice: "Netrc contains machine credentials. Do not expose to MCP servers." },
  { pattern: /0\.0\.0\.0/i, type: "Binds to all interfaces", severity: "medium", advice: "Bind to 127.0.0.1 (localhost) unless remote access is explicitly required." },
  { pattern: /--no-sandbox/i, type: "Sandbox disabled", severity: "high", advice: "Never disable sandboxing in production MCP servers." },
  { pattern: /--disable-web-security/i, type: "Web security disabled", severity: "critical", advice: "Disabling web security exposes the browser to cross-origin attacks." },
  { pattern: /--remote-debugging/i, type: "Remote debugging enabled", severity: "high", advice: "Remote debugging ports can be exploited for RCE." },
  { pattern: /sudo\s/i, type: "Elevated privileges (sudo)", severity: "critical", advice: "MCP servers should never run with sudo/root privileges." },
  { pattern: /--privileged/i, type: "Privileged mode", severity: "critical", advice: "Do not run MCP servers in Docker privileged mode." },
  { pattern: /chmod\s+777/i, type: "World-writable permissions", severity: "high", advice: "Never set 777 permissions in MCP server operations." },
];

// Structural config issues (checked at the config level, not per-value)
export const CONFIG_ISSUES = [
  {
    check: (serverConfig) => !serverConfig.env || Object.keys(serverConfig.env).length === 0,
    skipIf: (serverConfig) => {
      // Only flag for servers that typically need auth
      const pkg = (serverConfig.args || []).join(' ');
      const needsAuth = /slack|github|gitlab|stripe|notion|linear|supabase|datadog|sentry/i;
      return !needsAuth.test(pkg);
    },
    type: "missing_auth",
    severity: "medium",
    title: "No authentication configured",
    advice: "This server typically requires API keys or tokens. Ensure auth is configured via environment variables.",
  },
  {
    check: (serverConfig) => {
      const args = (serverConfig.args || []).join(' ');
      return /stdio/i.test(args) && /0\.0\.0\.0|--host|--port/i.test(args);
    },
    type: "mixed_transport",
    severity: "medium",
    title: "Mixed transport indicators",
    advice: "Server config appears to mix stdio and network transport. Verify intended transport mode.",
  },
];
