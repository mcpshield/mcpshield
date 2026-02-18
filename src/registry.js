// npm Registry Live Lookup
// Queries registry.npmjs.org to verify packages, check download counts,
// detect suspicious signals (low downloads, recent publish, no repo, etc.)

import https from 'https';

const REGISTRY_URL = 'https://registry.npmjs.org';
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-month';

/**
 * Make an HTTPS GET request and return parsed JSON
 */
function fetchJSON(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Request timed out')), timeoutMs);
    https.get(url, { headers: { 'Accept': 'application/json', 'User-Agent': 'mcpshield/0.1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        clearTimeout(timer);
        if (res.statusCode === 404) return resolve(null);
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Invalid JSON from ${url}`)); }
      });
      res.on('error', (e) => { clearTimeout(timer); reject(e); });
    }).on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

/**
 * Lookup a package on the npm registry
 * Returns: package metadata, download stats, and risk signals
 */
export async function lookupPackage(packageName) {
  const result = {
    name: packageName,
    exists: false,
    metadata: null,
    downloads: null,
    signals: [],
    error: null,
  };

  try {
    // Fetch package metadata
    const encodedName = packageName.replace('/', '%2f');
    const meta = await fetchJSON(`${REGISTRY_URL}/${encodedName}`);

    if (!meta) {
      result.exists = false;
      result.signals.push({
        type: "package_not_found",
        severity: "high",
        title: "Package not found on npm registry",
        detail: `${packageName} does not exist on npmjs.org. This may be a local/private package, or it may have been removed.`,
        advice: "Verify the package name is correct. If this is a private package, ensure it's from a trusted source.",
      });
      return result;
    }

    result.exists = true;
    const latest = meta['dist-tags']?.latest;
    const latestVersion = meta.versions?.[latest];
    const timeData = meta.time || {};

    result.metadata = {
      name: meta.name,
      version: latest,
      description: meta.description,
      author: typeof meta.author === 'string' ? meta.author : meta.author?.name,
      license: meta.license,
      homepage: meta.homepage,
      repository: meta.repository?.url || meta.repository,
      maintainers: (meta.maintainers || []).map(m => m.name || m),
      created: timeData.created,
      lastModified: timeData.modified,
      lastPublish: timeData[latest],
      hasPostinstall: !!latestVersion?.scripts?.postinstall,
      hasPreinstall: !!latestVersion?.scripts?.preinstall,
      hasPrepare: !!latestVersion?.scripts?.prepare,
      dependencies: Object.keys(latestVersion?.dependencies || {}),
      keywords: meta.keywords || [],
    };

    // ── Risk Signal Checks ────────────────────────────────────

    // Check for install scripts (common malware vector)
    if (result.metadata.hasPostinstall) {
      result.signals.push({
        type: "install_script",
        severity: "medium",
        title: "Package has postinstall script",
        detail: "Postinstall scripts execute arbitrary code during npm install and are a common malware delivery mechanism.",
        advice: "Review the postinstall script before installing. Use --ignore-scripts flag when testing.",
      });
    }
    if (result.metadata.hasPreinstall) {
      result.signals.push({
        type: "install_script",
        severity: "high",
        title: "Package has preinstall script",
        detail: "Preinstall scripts execute before any security checks and are a high-risk malware vector.",
        advice: "Inspect the preinstall script carefully. This is a red flag for supply chain attacks.",
      });
    }

    // Check for missing repository
    if (!result.metadata.repository) {
      result.signals.push({
        type: "no_repository",
        severity: "medium",
        title: "No source code repository linked",
        detail: "Package does not link to a source repository. Cannot verify code provenance.",
        advice: "Prefer packages with linked GitHub/GitLab repositories for code auditability.",
      });
    }

    // Check package age (very new packages are riskier)
    if (result.metadata.created) {
      const ageMs = Date.now() - new Date(result.metadata.created).getTime();
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays < 30) {
        result.signals.push({
          type: "new_package",
          severity: "high",
          title: `Package is only ${Math.round(ageDays)} days old`,
          detail: "Very recently published packages have a higher likelihood of being malicious.",
          advice: "Exercise extra caution with packages less than 30 days old. Wait for community vetting.",
        });
      } else if (ageDays < 90) {
        result.signals.push({
          type: "new_package",
          severity: "medium",
          title: `Package is only ${Math.round(ageDays)} days old`,
          detail: "Relatively new package. Less community review and testing.",
          advice: "Review the source code and maintainer history before trusting this package.",
        });
      }
    }

    // Check maintainer count (single anonymous maintainer = riskier)
    if (result.metadata.maintainers.length === 1) {
      result.signals.push({
        type: "single_maintainer",
        severity: "low",
        title: "Single maintainer",
        detail: `Package is maintained by a single account: ${result.metadata.maintainers[0]}`,
        advice: "Single-maintainer packages have higher bus-factor risk and potentially less review.",
      });
    }

    // Check for no description
    if (!result.metadata.description || result.metadata.description.length < 10) {
      result.signals.push({
        type: "no_description",
        severity: "low",
        title: "Missing or minimal package description",
        detail: "Legitimate packages typically have meaningful descriptions.",
        advice: "Review the package contents carefully before using.",
      });
    }

    // Fetch download stats
    try {
      const downloads = await fetchJSON(`${DOWNLOADS_URL}/${encodedName}`);
      if (downloads) {
        result.downloads = {
          lastMonth: downloads.downloads,
          period: downloads.start + ' to ' + downloads.end,
        };

        // Low downloads = potentially risky
        if (downloads.downloads < 100) {
          result.signals.push({
            type: "low_downloads",
            severity: "high",
            title: `Very low download count: ${downloads.downloads}/month`,
            detail: "Packages with fewer than 100 monthly downloads are more likely to be malicious or unmaintained.",
            advice: "Consider using a more established alternative. Low downloads often indicate abandonment or malicious intent.",
          });
        } else if (downloads.downloads < 1000) {
          result.signals.push({
            type: "low_downloads",
            severity: "medium",
            title: `Low download count: ${downloads.downloads}/month`,
            detail: "Moderate adoption. Less community oversight than popular packages.",
            advice: "Verify the package source and review recent changes before using.",
          });
        }
      }
    } catch (e) {
      // Download stats unavailable — not critical
    }

  } catch (e) {
    result.error = e.message;
    if (e.message.includes('timed out') || e.message.includes('ENOTFOUND') || e.message.includes('ECONNREFUSED')) {
      result.signals.push({
        type: "registry_unavailable",
        severity: "info",
        title: "npm registry check unavailable",
        detail: `Could not reach registry: ${e.message}`,
        advice: "Run with network access to enable live registry checks.",
      });
    }
  }

  return result;
}

/**
 * Format registry findings into standard finding format
 */
export function formatRegistryFindings(registryResult, serverName) {
  return registryResult.signals.map(s => ({
    server: serverName,
    package: registryResult.name,
    type: `registry_${s.type}`,
    severity: s.severity,
    title: s.title,
    detail: s.detail,
    advice: s.advice,
    registryData: {
      exists: registryResult.exists,
      downloads: registryResult.downloads?.lastMonth,
      maintainers: registryResult.metadata?.maintainers,
    },
  }));
}
