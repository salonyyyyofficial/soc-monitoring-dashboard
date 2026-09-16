/**
 * threatIntel.js
 *
 * Provider abstraction for threat intelligence lookups.
 * All providers are OPTIONAL - if no API keys are configured in .env,
 * lookups return a clear "not configured" result instead of throwing,
 * so the dashboard keeps working normally.
 *
 * API keys are read from process.env only and are NEVER sent to the browser.
 */

const PROVIDERS = {
  virustotal: {
    name: 'VirusTotal',
    envKey: 'VIRUSTOTAL_API_KEY',
    supports: ['IP', 'DOMAIN', 'HASH'],
  },
  abuseipdb: {
    name: 'AbuseIPDB',
    envKey: 'ABUSEIPDB_API_KEY',
    supports: ['IP'],
  },
  otx: {
    name: 'AlienVault OTX',
    envKey: 'OTX_API_KEY',
    supports: ['IP', 'DOMAIN', 'HASH'],
  },
};

function detectIndicatorType(indicator) {
  const value = (indicator || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'IP';
  if (/^[a-fA-F0-9]{32}$/.test(value) || /^[a-fA-F0-9]{40}$/.test(value) || /^[a-fA-F0-9]{64}$/.test(value)) return 'HASH';
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'DOMAIN';
  return null;
}

function configuredProviders() {
  return Object.entries(PROVIDERS)
    .filter(([, p]) => !!process.env[p.envKey])
    .map(([key, p]) => ({ key, name: p.name }));
}

/**
 * Local heuristic fallback used when no external provider is configured.
 * Flags the synthetic "attacker pool" IPs the simulator uses, so the
 * demo still shows a meaningful malicious/clean verdict offline.
 */
const KNOWN_BAD_DEMO_IPS = ['203.0.113.45', '198.51.100.23', '45.33.32.156', '185.220.101.7'];

function localHeuristic(indicator, type) {
  if (type === 'IP' && KNOWN_BAD_DEMO_IPS.includes(indicator)) {
    return {
      reputation: 'MALICIOUS',
      country: 'Unknown',
      provider: 'Local demo list',
      details: 'This IP appears in the simulator\'s synthetic attacker pool. Flagged for demonstration purposes only - it is not a real-world threat indicator.',
    };
  }
  if (type === 'IP' && indicator.startsWith('192.168.')) {
    return {
      reputation: 'CLEAN',
      country: 'Private range',
      provider: 'Local demo list',
      details: 'RFC1918 private address - internal host, not routable on the public internet.',
    };
  }
  return {
    reputation: 'UNKNOWN',
    country: null,
    provider: 'Local demo list',
    details: 'No external threat intelligence provider is configured, and this indicator is not in the local demo list.',
  };
}

/**
 * Looks up an indicator. Currently uses the local heuristic; real provider
 * HTTP calls can be dropped into the marked section once keys are supplied.
 *
 * @returns {{ indicator, indicator_type, reputation, country, provider, details, configured }}
 */
async function lookup(indicator) {
  const value = (indicator || '').trim();
  const type = detectIndicatorType(value);

  if (!type) {
    return {
      error: 'Unrecognized indicator. Enter a valid IP address, domain, or file hash (MD5/SHA1/SHA256).',
    };
  }

  const available = configuredProviders();

  // --- External provider calls would go here ---
  // Each provider needs its own fetch + response mapping. Left unimplemented
  // on purpose: without real API keys there is nothing to test against, and
  // the brief says the app must work with providers unconfigured.
  // if (available.length > 0) { ...call provider, map response... }

  const result = localHeuristic(value, type);

  return {
    indicator: value,
    indicator_type: type,
    reputation: result.reputation,
    country: result.country,
    provider: result.provider,
    details: result.details,
    configured: available.length > 0,
    availableProviders: available,
  };
}

module.exports = { lookup, detectIndicatorType, configuredProviders, PROVIDERS, KNOWN_BAD_DEMO_IPS };
