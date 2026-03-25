/**
 * Scan Engine — Capability Scorer
 * Calculates risk based on declared permissions
 */

import { PERMISSION_WEIGHTS } from '../constants.js';
import { normalizePermission } from '../utils/helpers.js';

/**
 * Score an extension's permissions
 * @param {Object} manifest
 * @returns {Object}
 */
export function calculateCapabilityScore(manifest) {
  if (!manifest) return { score: 0, permissions: [], highRiskPermissions: [], details: {} };

  const perms = new Set();

  const collect = (arr) => {
    if (!Array.isArray(arr)) return;
    arr.forEach(p => { const n = normalizePermission(p); if (n) perms.add(n); });
  };

  collect(manifest.permissions);
  collect(manifest.optional_permissions);
  collect(manifest.host_permissions);

  let total = 0;
  const details = {};

  for (const p of perms) {
    const w = PERMISSION_WEIGHTS[p] || 0;
    if (w > 0) { total += w; details[p] = w; }
  }

  return {
    score: total,
    permissions: Array.from(perms),
    details,
    highRiskPermissions: Object.entries(details)
      .filter(([, w]) => w >= 6)
      .map(([p]) => p),
  };
}

/**
 * Extract all host permissions (including content-script matches)
 */
export function extractHostPermissions(manifest) {
  if (!manifest) return [];
  const hosts = new Set();
  const add = (arr) => { if (Array.isArray(arr)) arr.forEach(h => hosts.add(h)); };

  // MV2: URLs in permissions
  if (Array.isArray(manifest.permissions)) {
    manifest.permissions.forEach(p => { if (isHost(p)) hosts.add(p); });
  }
  add(manifest.host_permissions);
  add(manifest.optional_host_permissions);

  // Content-script matches
  if (Array.isArray(manifest.content_scripts)) {
    manifest.content_scripts.forEach(cs => add(cs.matches));
  }
  return Array.from(hosts);
}

function isHost(p) {
  return p && (p.includes('://') || p === '<all_urls>' || p.startsWith('*') || p.startsWith('http') || p.startsWith('file'));
}

/**
 * Get human-readable descriptions for permissions
 */
export function getPermissionDescriptions(permissions) {
  const MAP = {
    cookies: 'Access and modify browser cookies',
    webRequest: 'Monitor network traffic',
    webRequestBlocking: 'Block or modify network requests',
    tabs: 'Access browser tab information',
    scripting: 'Inject and run scripts in pages',
    nativeMessaging: 'Communicate with native OS apps',
    debugger: 'Chrome DevTools debugger protocol',
    history: 'Read and modify browsing history',
    storage: 'Store data locally',
    bookmarks: 'Read and modify bookmarks',
    downloads: 'Manage downloads',
    clipboardRead: 'Read clipboard contents',
    clipboardWrite: 'Write to clipboard',
    geolocation: 'Access device location',
    notifications: 'Display notifications',
    management: 'Manage other extensions',
    pageCapture: 'Capture page content as MHTML',
    tabCapture: 'Capture visible tab content',
    desktopCapture: 'Screen capture/sharing',
    proxy: 'Manage proxy settings',
  };
  return permissions.reduce((acc, p) => { if (MAP[p]) acc[p] = MAP[p]; return acc; }, {});
}
