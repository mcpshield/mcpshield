#!/usr/bin/env node

// MCPShield — MCP Supply Chain Security Scanner
// Usage:
//   mcpshield scan                              Auto-discover and scan all MCP configs
//   mcpshield scan --config <path>              Scan a specific config file
//   mcpshield scan --config <path> --json       Output JSON report (for CI/CD)
//   mcpshield scan --config <path> --json --output report.json

import { discoverConfigs, parseConfig, loadConfig } from './config.js';
import { detectTyposquat, checkPublisher } from './typosquat.js';
import { scanCredentials } from './credentials.js';
import { extractPackageName, checkCVEs, formatCVEFindings } from './cvecheck.js';
import { lookupPackage, formatRegistryFindings } from './registry.js';
import { CONFIG_ISSUES } from '../data/vulndb.js';
import {
  printBanner, printSection, printServerHeader, printFinding,
  printTyposquatAlert, printPublisherWarning, printSummary,
  generateJSONReport
} from './output.js';
import { auditToolList } from './toolScanner.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ─── Parse CLI args ─────────────────────────────────────────────
function parseArgs(argv) {
  const args = argv.slice(2);
  const firstArg = args[0] || 'scan';
  const isCommand = !firstArg.startsWith('-');
  const command = isCommand ? firstArg : 'scan';

  const opts = {
    command,
    config: null,
    tools: null,
    json: false,
    output: null,
    verbose: false,
    help: false,
    network: true,
  };

  const startIndex = isCommand ? 1 : 0;
  for (let i = startIndex; i < args.length; i++) {
    switch (args[i]) {
      case '--config': case '-c':
        opts.config = args[++i]; break;
      case '--tools': case '-t':
        opts.tools = args[++i]; break;
      case '--json': case '-j':
        opts.json = true; break;
      case '--output': case '-o':
        opts.output = args[++i]; break;
      case '--verbose': case '-v':
        opts.verbose = true; break;
      case '--help': case '-h':
        opts.help = true; break;
      case '--no-network': case '--offline':
        opts.network = false; break;
      default:
        if (!args[i].startsWith('-') && !opts.tools && (command === 'audit-tools' || command === 'scan-tools')) {
          opts.tools = args[i];
        }
        break;
    }
  }

  return opts;
}

function printHelp() {
  console.log(`
${'\x1b[36m'}${'\x1b[1m'}MCPShield${'\x1b[0m'} — MCP Supply Chain Security Scanner

${'\x1b[1m'}USAGE${'\x1b[0m'}
  mcpshield scan                            Auto-discover and scan MCP configs
  mcpshield scan --config <path>            Scan a specific config file
  mcpshield audit-tools <path>              Audit an MCP tool definitions JSON file
  mcpshield scan --json                     Output JSON report
  mcpshield scan --json --output report.json  Save JSON to file

${'\x1b[1m'}OPTIONS${'\x1b[0m'}
  -c, --config <path>    Path to MCP config file (JSON)
  -t, --tools <path>     Path to MCP tool definitions file (JSON)
  -j, --json             Output as JSON (for CI/CD pipelines)
  -o, --output <path>    Write JSON report to file
  --no-network           Skip npm registry live lookups (offline mode)
  -v, --verbose          Show additional details
  -h, --help             Show this help message


${'\x1b[1m'}WHAT IT CHECKS${'\x1b[0m'}
  • Typosquat detection       Levenshtein distance + known malicious package DB
  • Known CVEs                MCP vulnerability database (40+ threats)
  • Hardcoded credentials     API keys, database URLs, tokens, private keys
  • Dangerous permissions     System dir access, disabled sandboxes, sudo
  • Publisher verification    Trusted scope and community verification
  • Transport security        HTTP vs HTTPS, missing auth on SSE
  • npm registry signals      Download counts, package age, install scripts
  • Config structural checks  Missing auth, mixed transports

${'\x1b[1m'}EXAMPLES${'\x1b[0m'}
  ${'\x1b[2m'}# Scan Claude Desktop config${'\x1b[0m'}
  mcpshield scan --config ~/Library/Application\\ Support/Claude/claude_desktop_config.json

  ${'\x1b[2m'}# Scan Cursor config${'\x1b[0m'}
  mcpshield scan --config .cursor/mcp.json

  ${'\x1b[2m'}# CI/CD: fail build on critical findings${'\x1b[0m'}
  mcpshield scan --config mcp.json --json --output mcpshield-report.json

  ${'\x1b[2m'}# Offline scan (skip npm registry checks)${'\x1b[0m'}
  mcpshield scan --config mcp.json --no-network

${'\x1b[1m'}EXIT CODES${'\x1b[0m'}
  0    No high/critical findings
  1    High-severity findings detected
  2    Critical findings detected (typosquats, RCE, etc.)
`);
}

// ─── Main scanner ───────────────────────────────────────────────
function scanConfig(config, source, quiet = false, enableNetwork = true) {
  const servers = parseConfig(config);
  const serverNames = Object.keys(servers);
  const allFindings = [];
  const registryPromises = [];

  let totalTyposquats = 0;
  let totalUnverified = 0;

  if (serverNames.length === 0) {
    if (!quiet) console.log(`  ${'⚠'} No MCP servers found in config.`);
    return { allFindings, totalTyposquats, totalUnverified, serverCount: 0, registryPromises };
  }

  for (const name of serverNames) {
    const serverConfig = servers[name];
    const packageName = extractPackageName(serverConfig);
    const serverFindings = [];

    if (!quiet) printServerHeader(name, packageName);

    // 1. Typosquat detection
    if (packageName) {
      const typosquatResult = detectTyposquat(packageName);
      if (typosquatResult) {
        totalTyposquats++;
        if (!quiet) printTyposquatAlert(typosquatResult, name);
        serverFindings.push({
          server: name,
          package: packageName,
          type: "typosquat",
          severity: typosquatResult.severity,
          title: typosquatResult.confidence === "confirmed"
            ? `MALICIOUS: ${typosquatResult.reason}`
            : `Potential typosquat of ${typosquatResult.target}`,
          detail: `Confidence: ${typosquatResult.confidence} | Distance: ${typosquatResult.distance} | Method: ${typosquatResult.method}`,
          advice: "Remove this server and replace with the legitimate package.",
        });
      }
    }

    // 2. Publisher verification
    if (packageName) {
      const publisherResult = checkPublisher(packageName);
      if (!publisherResult.trusted) {
        totalUnverified++;
        if (!quiet) printPublisherWarning(publisherResult, name);
        serverFindings.push({
          server: name,
          package: packageName,
          type: "unverified_publisher",
          severity: "medium",
          title: `Unverified publisher for ${packageName}`,
          detail: publisherResult.reason,
          advice: "Use packages from trusted scopes (@anthropic/, @modelcontextprotocol/) when possible.",
        });
      }
    }

    // 3. Known CVE check
    if (packageName) {
      const cveResult = checkCVEs(packageName);
      const cveFindings = formatCVEFindings(cveResult, name);
      serverFindings.push(...cveFindings.map(f => ({ server: name, package: packageName, ...f })));
    }

    // 4. Credential scan
    const credFindings = scanCredentials(serverConfig, name);
    serverFindings.push(...credFindings.map(f => ({ server: name, package: packageName, ...f })));

    // 5. Config-level structural checks
    for (const issue of CONFIG_ISSUES) {
      if (issue.skipIf && issue.skipIf(serverConfig)) continue;
      if (issue.check(serverConfig)) {
        serverFindings.push({
          server: name,
          package: packageName,
          type: issue.type,
          severity: issue.severity,
          title: issue.title,
          detail: `Server: ${name}`,
          advice: issue.advice,
        });
      }
    }

    // 6. Queue async npm registry lookup (runs in parallel)
    if (packageName && enableNetwork) {
      registryPromises.push(
        lookupPackage(packageName).then(result => ({
          serverName: name,
          findings: formatRegistryFindings(result, name),
          metadata: result.metadata,
          downloads: result.downloads,
        })).catch(() => ({ serverName: name, findings: [], metadata: null, downloads: null }))
      );
    }

    // Print findings for this server
    if (!quiet) {
      if (serverFindings.length > 0) {
        console.log();
        serverFindings.forEach((f, i) => printFinding(f, i + 1));
      } else {
        console.log(`  ${'✓'} \x1b[32mNo issues found\x1b[0m\n`);
      }
    }

    allFindings.push(...serverFindings);
  }

  return { allFindings, totalTyposquats, totalUnverified, serverCount: serverNames.length, registryPromises };
}

// ─── Entry point ────────────────────────────────────────────────
async function main() {
  const opts = parseArgs(process.argv);

  if (opts.help || opts.command === 'help') {
    printHelp();
    process.exit(0);
  }

  if (!opts.json) {
    printBanner();
  }

  // Handle MCP tool definition auditing
  if (opts.command === 'audit-tools' || opts.command === 'scan-tools' || opts.tools) {
    const targetFile = opts.tools || opts.config;
    if (!targetFile) {
      console.error(`\x1b[31mError: Please provide a tools definition JSON file (e.g. mcpshield audit-tools <tools.json> or -t <path>)\x1b[0m`);
      process.exit(1);
    }

    const resolvedPath = resolve(targetFile);
    if (!existsSync(resolvedPath)) {
      console.error(`\x1b[31mError: Tools file not found: ${resolvedPath}\x1b[0m`);
      process.exit(1);
    }

    let raw;
    try {
      raw = readFileSync(resolvedPath, 'utf8');
    } catch (err) {
      console.error(`\x1b[31mError reading file: ${err.message}\x1b[0m`);
      process.exit(1);
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      console.error(`\x1b[31mError parsing JSON: ${err.message}\x1b[0m`);
      process.exit(1);
    }

    const tools = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.tools) ? parsed.tools : []);
    if (!opts.json) {
      printSection(`AUDITING MCP TOOLS: ${targetFile}`);
      console.log(`  \x1b[2mFound ${tools.length} tool definition(s)\x1b[0m\n`);
    }

    const { alerts, summary } = auditToolList(tools);

    const findings = alerts.map(a => ({
      server: `Tool: ${a.toolName}`,
      package: a.category,
      type: a.category.toLowerCase(),
      severity: a.severity.toLowerCase(),
      title: a.title,
      detail: a.description + (a.matchedSnippet ? ` [Matched: "${a.matchedSnippet}"]` : ''),
      advice: a.remediation,
    }));

    if (!opts.json) {
      if (findings.length > 0) {
        findings.forEach((f, i) => printFinding(f, i + 1));
      } else {
        console.log(`  ✓ \x1b[32mNo vulnerabilities found in tool definitions.\x1b[0m\n`);
      }
    }

    const bySeverity = {
      critical: summary.critical,
      high: summary.high,
      medium: summary.medium,
      low: 0,
    };

    const summaryData = {
      totalServers: summary.totalTools,
      totalFindings: summary.totalAlerts,
      bySeverity,
      typosquats: 0,
      unverified: 0,
    };

    if (opts.json) {
      const report = generateJSONReport(summaryData, findings);
      report.tools_audited = summary.totalTools;
      if (opts.output) {
        writeFileSync(opts.output, JSON.stringify(report, null, 2));
        console.error(`Report written to ${opts.output}`);
      } else {
        console.log(JSON.stringify(report, null, 2));
      }
    } else {
      printSummary(summaryData);
    }

    if (summary.critical > 0) process.exit(2);
    if (summary.high > 0) process.exit(1);
    process.exit(0);
  }

  let configs = [];

  if (opts.config) {
    // Scan a specific config file
    try {
      const config = loadConfig(opts.config);
      configs.push({ path: resolve(opts.config), client: 'User-specified', config });
    } catch (err) {
      console.error(`\x1b[31mError: ${err.message}\x1b[0m`);
      process.exit(1);
    }
  } else {
    // Auto-discover configs
    if (!opts.json) {
      printSection('DISCOVERING MCP CONFIGS');
    }
    configs = discoverConfigs();

    if (configs.length === 0) {
      if (!opts.json) {
        console.log('  No MCP configuration files found.');
        console.log('  \x1b[2mUse --config <path> to specify a config file manually.\x1b[0m\n');
        console.log('  \x1b[2mSearched locations include:\x1b[0m');
        console.log('  \x1b[2m  • ~/Library/Application Support/Claude/claude_desktop_config.json\x1b[0m');
        console.log('  \x1b[2m  • ~/.cursor/mcp.json\x1b[0m');
        console.log('  \x1b[2m  • .vscode/mcp.json\x1b[0m');
        console.log('  \x1b[2m  • mcp.json (project root)\x1b[0m\n');
      }
      process.exit(0);
    }

    if (!opts.json) {
      configs.forEach(c => {
        console.log(`  ${'✓'} \x1b[32m${c.client}\x1b[0m`);
        console.log(`    \x1b[2m${c.path}\x1b[0m`);
      });
    }
  }

  // Run scans
  let totalFindings = [];
  let totalServers = 0;
  let totalTyposquats = 0;
  let totalUnverified = 0;
  let allRegistryPromises = [];

  for (const { path, client, config } of configs) {
    if (!opts.json) {
      printSection(`SCANNING: ${client}`);
      console.log(`  \x1b[2m${path}\x1b[0m\n`);
    }

    const result = scanConfig(config, path, opts.json, opts.network);
    totalFindings.push(...result.allFindings);
    totalServers += result.serverCount;
    totalTyposquats += result.totalTyposquats;
    totalUnverified += result.totalUnverified;
    allRegistryPromises.push(...(result.registryPromises || []));
  }

  // Await registry lookups (run in parallel with local scans)
  if (allRegistryPromises.length > 0) {
    if (!opts.json) {
      printSection('NPM REGISTRY CHECKS');
    }
    try {
      const registryResults = await Promise.all(allRegistryPromises);
      for (const rr of registryResults) {
        if (rr.findings.length > 0) {
          if (!opts.json) {
            console.log(`  \x1b[1m📡 ${rr.serverName}\x1b[0m${rr.downloads ? ` \x1b[2m(${rr.downloads.lastMonth.toLocaleString()} downloads/month)\x1b[0m` : ''}`);
            rr.findings.forEach((f, i) => printFinding(f, i + 1));
          }
          totalFindings.push(...rr.findings);
        } else if (!opts.json && rr.metadata) {
          console.log(`  \x1b[1m📡 ${rr.serverName}\x1b[0m \x1b[32m✓ registry OK\x1b[0m \x1b[2m(${rr.downloads?.lastMonth?.toLocaleString() || '?'} downloads/month)\x1b[0m`);
        }
      }
    } catch (e) {
      if (!opts.json) {
        console.log(`  \x1b[2mRegistry checks unavailable: ${e.message}\x1b[0m`);
      }
    }
  }

  // Aggregate results
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of totalFindings) {
    if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
  }

  const summaryData = {
    totalServers,
    totalFindings: totalFindings.length,
    bySeverity,
    typosquats: totalTyposquats,
    unverified: totalUnverified,
  };

  if (opts.json) {
    const report = generateJSONReport(summaryData, totalFindings);
    if (opts.output) {
      writeFileSync(opts.output, JSON.stringify(report, null, 2));
      console.error(`Report written to ${opts.output}`);
    } else {
      console.log(JSON.stringify(report, null, 2));
    }
  } else {
    printSummary(summaryData);
  }

  // Exit code based on severity
  if (bySeverity.critical > 0) process.exit(2);
  if (bySeverity.high > 0) process.exit(1);
  process.exit(0);
}

main().catch(err => {
  console.error(`\x1b[31mFatal error: ${err.message}\x1b[0m`);
  process.exit(1);
});
