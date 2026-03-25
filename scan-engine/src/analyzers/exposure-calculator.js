/**
 * Scan Engine — Exposure Calculator
 * Analyses host-permission scope and calculates risk multiplier
 */

import { EXPOSURE_MULTIPLIERS } from '../constants.js';
import { categorizeHostPermissions } from '../utils/helpers.js';

/**
 * Calculate exposure multiplier from host permissions
 */
export function calculateExposureMultiplier(hostPermissions) {
  if (!hostPermissions || hostPermissions.length === 0) {
    return {
      multiplier: EXPOSURE_MULTIPLIERS.NO_HOSTS,
      category: 'NO_HOSTS',
      analysis: { totalHosts: 0, hasAllUrls: false, hasWildcards: false, hasFileAccess: false, domains: [], wildcardDomains: [], specificDomains: [] },
    };
  }
  const analysis = analyzeHosts(hostPermissions);
  const category = categorizeHostPermissions(hostPermissions);
  return { multiplier: EXPOSURE_MULTIPLIERS[category] || 1.0, category, analysis };
}

function analyzeHosts(hosts) {
  const a = {
    totalHosts: hosts.length,
    hasAllUrls: false, hasWildcards: false, hasFileAccess: false, hasLocalhost: false,
    domains: [], wildcardDomains: [], specificDomains: [],
  };
  for (const h of hosts) {
    if (isAll(h)) { a.hasAllUrls = true; continue; }
    if (h.startsWith('file://')) { a.hasFileAccess = true; continue; }
    if (/localhost|127\.0\.0\.1/.test(h)) { a.hasLocalhost = true; continue; }
    const d = extractDomain(h);
    if (d) {
      a.domains.push(d);
      (h.includes('*') ? a.wildcardDomains : a.specificDomains).push(d);
      if (h.includes('*')) a.hasWildcards = true;
    }
  }
  return a;
}

function isAll(h) {
  return h === '<all_urls>' || h === '*://*/*' || h === 'http://*/*' || h === 'https://*/*';
}

function extractDomain(h) {
  try {
    let c = h.replace(/^\*:\/\//, 'https://').replace(/^https?:\/\//, '');
    return c.split('/')[0].split(':')[0] || null;
  } catch { return null; }
}

export function calculateExposureScore(capScore, multiplier) {
  return capScore * multiplier;
}

export function isExposureLimited(category) {
  return ['NO_HOSTS', 'SINGLE_DOMAIN', 'MULTIPLE_DOMAINS'].includes(category);
}

export function getExposureDescription(cat) {
  const m = {
    NO_HOSTS: 'No host access — extension operates locally',
    SINGLE_DOMAIN: 'Limited to a single domain',
    MULTIPLE_DOMAINS: 'Access to several specific domains',
    WILDCARD_SUBDOMAIN: 'Wildcard access across sub-domains',
    ALL_URLS: 'Access to ALL websites',
    FILE_ACCESS: 'Can read local files',
  };
  return m[cat] || 'Unknown';
}
