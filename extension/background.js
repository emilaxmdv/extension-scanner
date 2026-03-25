/**
 * Extension Scanner — Background Service Worker
 * Handles CRX downloading, installed extension lookups, and message routing
 */

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkInstalled') {
    checkInstalled(request.extensionId).then(
      data => sendResponse({ success: true, data }),
      err  => sendResponse({ success: false, error: err.message })
    );
    return true;
  }

  if (request.action === 'getInstalledExtensions') {
    chrome.management.getAll().then(
      exts => sendResponse({ success: true, data: exts.filter(e => e.type === 'extension' && e.id !== chrome.runtime.id) }),
      err  => sendResponse({ success: false, error: err.message })
    );
    return true;
  }
});

/**
 * Check if extension is installed — returns manifest data or null
 * Lightweight: no CRX download, no large message
 */
async function checkInstalled(extensionId) {
  const all = await chrome.management.getAll();
  const ext = all.find(e => e.id === extensionId);
  if (!ext) return null;

  return {
    name: ext.name,
    manifest: {
      manifest_version: 3,
      name: ext.name,
      version: ext.version,
      description: ext.description || '',
      permissions: ext.permissions || [],
      host_permissions: ext.hostPermissions || [],
    },
    jsFiles: [],
  };
}

// ─── Lifecycle ───────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(details => {
  if (details.reason === 'install') {
    chrome.storage.local.set({ installedDate: Date.now(), version: chrome.runtime.getManifest().version });
  }
});

chrome.management.onInstalled?.addListener(info => {
  chrome.storage.local.get(['autoScan'], r => {
    if (r.autoScan) console.log('[Scanner] Auto-scan triggered for', info.name);
  });
});
