// Credential scanner — detects hardcoded secrets, dangerous permissions,
// and insecure configuration patterns in MCP server configs

import { CREDENTIAL_PATTERNS, DANGEROUS_PERMISSIONS } from '../data/vulndb.js';

/**
 * Deep-scan a value (string) for credential patterns
 */
function scanValue(value, path) {
  const findings = [];

  if (typeof value !== 'string') return findings;

  for (const rule of CREDENTIAL_PATTERNS) {
    if (rule.pattern.test(value)) {
      // Mask the credential in the output
      const masked = value.replace(/([^:\/]{3})[^:\/\s@]{4,}/g, '$1****');
      findings.push({
        type: "hardcoded_credential",
        severity: rule.severity,
        title: `${rule.type} detected in config`,
        detail: `Found at: ${path}`,
        value: masked,
        advice: rule.advice,
      });
    }
  }

  return findings;
}

/**
 * Scan args array and env vars for dangerous permissions
 */
function scanPermissions(args, env, serverName) {
  const findings = [];
  const allValues = [
    ...(args || []).map((a, i) => ({ val: a, path: `${serverName}.args[${i}]` })),
    ...Object.entries(env || {}).map(([k, v]) => ({ val: v, path: `${serverName}.env.${k}` })),
  ];

  for (const { val, path } of allValues) {
    if (typeof val !== 'string') continue;
    for (const rule of DANGEROUS_PERMISSIONS) {
      if (rule.pattern.test(val)) {
        findings.push({
          type: "dangerous_permission",
          severity: rule.severity,
          title: `${rule.type}`,
          detail: `Found at: ${path}`,
          value: val,
          advice: rule.advice,
        });
      }
    }
  }

  return findings;
}

/**
 * Check for insecure transport / missing auth patterns
 */
function scanTransport(serverConfig, serverName) {
  const findings = [];
  const args = (serverConfig.args || []).join(' ');
  const env = serverConfig.env || {};

  // Check for HTTP (non-HTTPS) URLs
  const httpPattern = /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i;
  if (httpPattern.test(args) || Object.values(env).some(v => typeof v === 'string' && httpPattern.test(v))) {
    findings.push({
      type: "insecure_transport",
      severity: "high",
      title: "Non-HTTPS URL detected",
      detail: `Server ${serverName} connects over unencrypted HTTP`,
      advice: "Use HTTPS for all remote MCP server connections to prevent credential interception.",
    });
  }

  // Check if SSE transport is used without auth headers
  if (args.includes('sse') || serverConfig.transport === 'sse') {
    if (!args.includes('auth') && !env.AUTH_TOKEN && !env.API_KEY && !env.BEARER_TOKEN) {
      findings.push({
        type: "missing_auth",
        severity: "medium",
        title: "SSE transport without visible authentication",
        detail: `Server ${serverName} uses SSE transport but no auth token is configured`,
        advice: "Ensure SSE connections use OAuth or bearer token authentication.",
      });
    }
  }

  return findings;
}

/**
 * Check for env vars that contain secrets directly vs. referencing system env
 */
function scanEnvValues(env, serverName) {
  const findings = [];

  for (const [key, value] of Object.entries(env || {})) {
    if (typeof value !== 'string') continue;

    // Check if it looks like a direct secret vs. an env var reference
    const sensitiveKeys = /key|token|secret|password|credential|auth|bearer/i;
    if (sensitiveKeys.test(key)) {
      // If the value doesn't look like an env var reference ($VAR or ${VAR})
      if (!value.startsWith('$') && !value.startsWith('${') && value.length > 5) {
        findings.push({
          type: "inline_secret",
          severity: "high",
          title: `Secret value inlined for ${key}`,
          detail: `${serverName}.env.${key} contains a direct value instead of an env reference`,
          value: value.substring(0, 4) + '****',
          advice: `Use an environment variable reference: "${key}": "$${key}" and set it in your shell environment.`,
        });
      }
    }

    // Also run credential pattern matching on env values
    findings.push(...scanValue(value, `${serverName}.env.${key}`));
  }

  return findings;
}

/**
 * Main credential scan: run all checks on a server config
 */
export function scanCredentials(serverConfig, serverName) {
  const findings = [];

  // Scan all args for credentials
  for (let i = 0; i < (serverConfig.args || []).length; i++) {
    findings.push(...scanValue(serverConfig.args[i], `${serverName}.args[${i}]`));
  }

  // Scan env vars
  findings.push(...scanEnvValues(serverConfig.env, serverName));

  // Scan permissions
  findings.push(...scanPermissions(serverConfig.args, serverConfig.env, serverName));

  // Scan transport security
  findings.push(...scanTransport(serverConfig, serverName));

  // Deduplicate by title+detail
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.title}:${f.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
