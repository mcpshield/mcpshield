// Terminal output formatting — colors, tables, and report generation

// ANSI color codes
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgGreen: '\x1b[42m',
  bgBlue: '\x1b[44m',
  bgMagenta: '\x1b[45m',
};

export const SEVERITY_COLORS = {
  critical: c.bgRed + c.white + c.bold,
  high: c.red + c.bold,
  medium: c.yellow,
  low: c.blue,
  info: c.dim,
};

export const SEVERITY_LABELS = {
  critical: `${c.bgRed}${c.white}${c.bold} CRITICAL ${c.reset}`,
  high: `${c.red}${c.bold} HIGH ${c.reset}`,
  medium: `${c.yellow} MEDIUM ${c.reset}`,
  low: `${c.blue} LOW ${c.reset}`,
  info: `${c.dim} INFO ${c.reset}`,
};

export function printBanner() {
  console.log(`
${c.cyan}${c.bold}  ╔═══════════════════════════════════════════╗
  ║                                           ║
  ║   ⛨  MCPShield v0.1.0                     ║
  ║   MCP Supply Chain Security Scanner        ║
  ║                                           ║
  ╚═══════════════════════════════════════════╝${c.reset}
`);
}

export function printSection(title) {
  console.log(`\n${c.cyan}${c.bold}─── ${title} ${'─'.repeat(Math.max(0, 50 - title.length))}${c.reset}\n`);
}

export function printServerHeader(name, packageName) {
  console.log(`${c.bold}📦 ${name}${c.reset}${packageName ? c.dim + ` (${packageName})` + c.reset : ''}`);
}

export function printFinding(finding, index) {
  const sev = SEVERITY_LABELS[finding.severity] || finding.severity;
  const prefix = `  ${c.dim}${String(index).padStart(2, ' ')}.${c.reset}`;
  console.log(`${prefix} ${sev} ${c.bold}${finding.title}${c.reset}`);
  if (finding.detail) console.log(`      ${c.dim}${finding.detail}${c.reset}`);
  if (finding.cvss) console.log(`      ${c.dim}CVSS: ${finding.cvss}${c.reset}`);
  if (finding.fixed) console.log(`      ${c.dim}${finding.fixed}${c.reset}`);
  if (finding.advice) console.log(`      ${c.green}↳ ${finding.advice}${c.reset}`);
  console.log();
}

export function printTyposquatAlert(result, serverName) {
  if (result.confidence === "confirmed") {
    console.log(`  ${c.bgRed}${c.white}${c.bold} 🛑 MALICIOUS PACKAGE DETECTED ${c.reset}`);
    console.log(`  ${c.red}${c.bold}${result.reason}${c.reset}`);
    console.log(`  ${c.dim}Impersonates: ${result.target} (distance: ${result.distance})${c.reset}`);
    console.log(`  ${c.red}${c.bold}↳ REMOVE THIS SERVER IMMEDIATELY${c.reset}`);
  } else {
    console.log(`  ${c.bgYellow}${c.bold} ⚠ POTENTIAL TYPOSQUAT ${c.reset}`);
    console.log(`  ${c.yellow}Similar to legitimate package: ${c.bold}${result.target}${c.reset}`);
    console.log(`  ${c.dim}Confidence: ${result.confidence} | Method: ${result.method} | Similarity: ${result.similarity}${c.reset}`);
    console.log(`  ${c.yellow}↳ Verify this is the intended package before using.${c.reset}`);
  }
  console.log();
}

export function printPublisherWarning(result, serverName) {
  if (!result.trusted) {
    console.log(`  ${c.yellow}⚠ Unverified publisher${c.reset} ${c.dim}— ${result.reason}${c.reset}`);
  }
}

export function printSummary(results) {
  const { totalServers, totalFindings, bySeverity, typosquats, unverified } = results;

  printSection('SCAN SUMMARY');

  console.log(`  ${c.bold}Servers scanned:${c.reset}  ${totalServers}`);
  console.log(`  ${c.bold}Total findings:${c.reset}   ${totalFindings}`);
  console.log();

  if (bySeverity.critical > 0)
    console.log(`  ${SEVERITY_LABELS.critical}  ${bySeverity.critical} finding${bySeverity.critical !== 1 ? 's' : ''}`);
  if (bySeverity.high > 0)
    console.log(`  ${SEVERITY_LABELS.high}  ${bySeverity.high} finding${bySeverity.high !== 1 ? 's' : ''}`);
  if (bySeverity.medium > 0)
    console.log(`  ${SEVERITY_LABELS.medium}  ${bySeverity.medium} finding${bySeverity.medium !== 1 ? 's' : ''}`);
  if (bySeverity.low > 0)
    console.log(`  ${SEVERITY_LABELS.low}  ${bySeverity.low} finding${bySeverity.low !== 1 ? 's' : ''}`);

  if (typosquats > 0)
    console.log(`\n  ${c.bgRed}${c.white}${c.bold} ⛨ ${typosquats} typosquat(s) detected — immediate action required ${c.reset}`);

  if (unverified > 0)
    console.log(`  ${c.yellow}⚠ ${unverified} server(s) from unverified publishers${c.reset}`);

  if (totalFindings === 0) {
    console.log(`\n  ${c.green}${c.bold}✓ No issues found. Your MCP config looks clean.${c.reset}`);
  }

  // Exit code guidance
  console.log(`\n${c.dim}─────────────────────────────────────────────────────${c.reset}`);
  if (bySeverity.critical > 0) {
    console.log(`  ${c.red}${c.bold}Exit code: 2 (critical findings)${c.reset}`);
  } else if (bySeverity.high > 0) {
    console.log(`  ${c.yellow}Exit code: 1 (high-severity findings)${c.reset}`);
  } else {
    console.log(`  ${c.green}Exit code: 0 (pass)${c.reset}`);
  }
  console.log();
}

/**
 * Generate a JSON report for CI/CD integration
 */
export function generateJSONReport(results, findings) {
  return {
    scanner: "mcpshield",
    version: "0.1.0",
    timestamp: new Date().toISOString(),
    summary: {
      servers_scanned: results.totalServers,
      total_findings: results.totalFindings,
      by_severity: results.bySeverity,
      typosquats_detected: results.typosquats,
      unverified_publishers: results.unverified,
      pass: results.bySeverity.critical === 0 && results.bySeverity.high === 0,
    },
    findings: findings,
  };
}
