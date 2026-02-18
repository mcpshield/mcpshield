// CVE checker — matches MCP servers in config against known vulnerability database

import { KNOWN_VULNS } from '../data/vulndb.js';

/**
 * Extract the package name from an MCP server config.
 *
 * Handles common patterns:
 *  - npx -y @scope/package-name
 *  - npx @scope/package-name
 *  - npx -y package-name
 *  - node path/to/server.js  (returns null — local server)
 *  - uvx package-name
 *  - command: "package-name" directly
 */
export function extractPackageName(serverConfig) {
  const args = serverConfig.args || [];
  const command = serverConfig.command || '';

  // If command is npx or uvx, find the package name in args
  if (command === 'npx' || command === 'uvx') {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      // Skip flags
      if (arg.startsWith('-')) continue;
      // This should be the package name
      // Handle @scope/name and plain name
      if (arg.startsWith('@') || !arg.includes('/')) {
        return arg;
      }
    }
  }

  // If command is node/python, it's a local server — can't check CVEs by package name
  if (command === 'node' || command === 'python' || command === 'python3') {
    return null;
  }

  // If command itself looks like a package name (e.g., "mcp-server-github")
  if (command.startsWith('mcp-') || command.startsWith('@')) {
    return command;
  }

  return null;
}

/**
 * Check a package against the known vulnerability database
 */
export function checkCVEs(packageName) {
  if (!packageName) return { found: false, vulnerabilities: [] };

  const entry = KNOWN_VULNS[packageName];
  if (!entry) {
    return { found: false, vulnerabilities: [], note: "Not in vulnerability database (may still have undiscovered issues)" };
  }

  return {
    found: true,
    package: entry.package,
    verified: entry.verified,
    vulnerabilities: entry.vulnerabilities.map(v => ({
      ...v,
      type: "known_cve",
    })),
  };
}

/**
 * Format CVE findings into the standard finding format
 */
export function formatCVEFindings(cveResult, serverName) {
  if (!cveResult.found || cveResult.vulnerabilities.length === 0) return [];

  return cveResult.vulnerabilities.map(v => ({
    type: "known_vulnerability",
    severity: v.severity,
    title: `${v.id}: ${v.title}`,
    detail: `Affects ${serverName} (${cveResult.package})`,
    description: v.description,
    cvss: v.cvss,
    fixed: v.fixed ? `Fixed in ${v.fixed}` : "No fix available",
    advice: v.fixed
      ? `Upgrade to version ${v.fixed} or later.`
      : "No patch available. Consider using an alternative server or implementing additional controls.",
    references: v.references,
  }));
}
