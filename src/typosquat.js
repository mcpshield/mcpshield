// Typosquat detection engine for MCP server packages
// Uses Levenshtein distance, character transposition, and common substitution patterns

import { KNOWN_LEGITIMATE_PACKAGES, KNOWN_MALICIOUS } from '../data/vulndb.js';

/**
 * Compute Levenshtein distance between two strings
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Check for common character substitutions used in typosquatting
 */
const CONFUSABLE_PAIRS = [
  ['l', '1'], ['l', 'i'], ['0', 'o'], ['rn', 'm'],
  ['vv', 'w'], ['cl', 'd'], ['nn', 'm'], ['ii', 'u'],
];

function hasConfusableSubstitution(name, legitimate) {
  for (const [fake, real] of CONFUSABLE_PAIRS) {
    if (name.includes(fake) && name.replace(fake, real) === legitimate) return true;
    if (name.includes(real) && name.replace(real, fake) === legitimate) return true;
  }
  return false;
}

/**
 * Check if a character was dropped, added, or transposed
 */
function isTransposition(a, b) {
  if (Math.abs(a.length - b.length) > 1) return false;
  let diffs = 0;
  const shorter = a.length <= b.length ? a : b;
  const longer = a.length > b.length ? a : b;

  if (a.length === b.length) {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) diffs++;
    }
    return diffs <= 2; // Allow 1-2 char swaps
  }
  return true; // Length diff of 1 is already suspicious at low Levenshtein
}

/**
 * Detect if a package name is a potential typosquat of a known legitimate package
 * Returns: { isTyposquat: bool, target: string, distance: int, method: string } | null
 */
export function detectTyposquat(packageName) {
  // First check the known-malicious list
  const knownMalicious = KNOWN_MALICIOUS.find(m => m.name === packageName);
  if (knownMalicious) {
    return {
      isTyposquat: true,
      confidence: "confirmed",
      target: knownMalicious.impersonates,
      reason: knownMalicious.reason,
      severity: knownMalicious.severity,
      distance: levenshtein(packageName, knownMalicious.impersonates),
    };
  }

  // Skip if it IS a known legitimate package
  if (KNOWN_LEGITIMATE_PACKAGES.includes(packageName)) {
    return null;
  }

  // Check against all legitimate packages
  const candidates = [];
  for (const legitimate of KNOWN_LEGITIMATE_PACKAGES) {
    const dist = levenshtein(packageName, legitimate);
    const maxLen = Math.max(packageName.length, legitimate.length);
    const similarity = 1 - (dist / maxLen);

    // Flag if very close to a legitimate package
    if (dist > 0 && dist <= 3 && similarity > 0.75) {
      let method = "edit distance";
      if (dist === 1) method = "single character difference";
      if (isTransposition(packageName, legitimate)) method = "character transposition";
      if (hasConfusableSubstitution(packageName, legitimate)) method = "confusable substitution";

      candidates.push({
        isTyposquat: true,
        confidence: dist === 1 ? "high" : dist === 2 ? "medium" : "low",
        target: legitimate,
        distance: dist,
        similarity: (similarity * 100).toFixed(1) + "%",
        method,
        severity: dist === 1 ? "critical" : "high",
      });
    }
  }

  // Return the closest match
  if (candidates.length > 0) {
    candidates.sort((a, b) => a.distance - b.distance);
    return candidates[0];
  }

  return null;
}

/**
 * Check if a package is from a known/verified publisher
 */
export function checkPublisher(packageName) {
  const trustedScopes = [
    "@anthropic/",
    "@modelcontextprotocol/",
    "@microsoft/",
    "@google/",
    "@stripe/",
    "@cloudflare/",
    "@vercel/",
    "@supabase/",
  ];

  for (const scope of trustedScopes) {
    if (packageName.startsWith(scope)) {
      return { trusted: true, scope, reason: `Published under trusted scope ${scope}` };
    }
  }

  if (KNOWN_LEGITIMATE_PACKAGES.includes(packageName)) {
    return { trusted: true, scope: "community-verified", reason: "Listed in verified community packages" };
  }

  return { trusted: false, scope: null, reason: "Unknown publisher — not from a trusted scope or verified list" };
}
