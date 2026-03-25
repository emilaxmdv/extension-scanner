/**
 * Scan Engine — Utility Functions
 * Shannon entropy, base64 detection, variable analysis, host categorization
 */

/**
 * Calculate Shannon entropy of a string
 * @param {string} str
 * @returns {number} bits per character
 */
export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if string looks like Base64
 */
export function isBase64(str) {
  if (!str || str.length < 4) return false;
  return /^[A-Za-z0-9+/]+=*$/.test(str) && str.length % 4 === 0;
}

/**
 * Extract Base64 strings from code
 */
export function extractBase64Strings(code) {
  const results = [];
  const re = /["'`]([A-Za-z0-9+/]{20,}=*)["'`]/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    if (isBase64(m[1])) results.push({ value: m[1], length: m[1].length });
  }
  return results;
}

/**
 * Analyse variable-name quality
 */
export function analyzeVariableNames(identifiers) {
  if (!identifiers || identifiers.length === 0) {
    return { total: 0, shortRatio: 0, veryShortRatio: 0, averageLength: 0 };
  }
  let short = 0, veryShort = 0, totalLen = 0;
  for (const name of identifiers) {
    totalLen += name.length;
    if (name.length <= 2) { veryShort++; short++; }
    else if (name.length < 4) short++;
  }
  return {
    total: identifiers.length,
    shortRatio: short / identifiers.length,
    veryShortRatio: veryShort / identifiers.length,
    averageLength: totalLen / identifiers.length,
  };
}

/**
 * Calculate code-density metrics
 */
export function calculateCodeDensity(code) {
  if (!code) return { totalChars: 0, totalLines: 0, charsPerLine: 0, nonEmptyLines: 0 };
  const lines = code.split('\n');
  const nonEmpty = lines.filter(l => l.trim().length > 0).length;
  return {
    totalChars: code.length,
    totalLines: lines.length,
    nonEmptyLines: nonEmpty,
    charsPerLine: nonEmpty > 0 ? code.length / nonEmpty : 0,
  };
}

/**
 * Categorise host-permission scope
 */
export function categorizeHostPermissions(hosts) {
  if (!hosts || hosts.length === 0) return 'NO_HOSTS';
  const allUrl = hosts.some(h =>
    h === '<all_urls>' || h === '*://*/*' || h === 'http://*/*' || h === 'https://*/*'
  );
  if (allUrl) return 'ALL_URLS';
  if (hosts.some(h => h.startsWith('file://'))) return 'FILE_ACCESS';
  if (hosts.some(h => h.includes('*') && h !== '<all_urls>')) return 'WILDCARD_SUBDOMAIN';
  if (hosts.length > 3) return 'MULTIPLE_DOMAINS';
  return 'SINGLE_DOMAIN';
}

/**
 * Check if URL is external (not localhost)
 */
export function isExternalUrl(url) {
  if (!url) return false;
  if (/^https?:\/\//.test(url)) return !/^https?:\/\/(localhost|127\.0\.0\.1)/.test(url);
  if (/^wss?:\/\//.test(url)) return true;
  return false;
}

/**
 * Normalise a permission string — strip URL patterns
 */
export function normalizePermission(perm) {
  if (!perm) return '';
  if (perm.includes('://')) return null;
  return perm.trim();
}

/** Cap a number */
export function cap(v, max) { return Math.min(v, max); }

/** Map score → risk-level label */
export function getRiskLevel(score, levels) {
  for (const lvl of Object.values(levels)) {
    if (score >= lvl.min && score <= lvl.max) return lvl.label;
  }
  return 'Unknown';
}

/** Deduplicate array */
export function unique(arr) { return [...new Set(arr)]; }
