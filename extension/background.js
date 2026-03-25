/**
 * Extension Scanner — Background Service Worker
 * Handles CRX downloading, installed extension lookups, and message routing
 */

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'fetchWebStoreExtension') {
    handleFetch(request.extensionId).then(
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

async function handleFetch(extensionId) {
  // Check if installed first
  const all = await chrome.management.getAll();
  const installed = all.find(e => e.id === extensionId);

  if (installed) {
    return {
      source: 'installed',
      name: installed.name,
      manifest: {
        manifest_version: installed.installType === 'development' ? 3 : (installed.mayDisable ? 3 : 2),
        name: installed.name,
        version: installed.version,
        description: installed.description || '',
        permissions: installed.permissions || [],
        host_permissions: installed.hostPermissions || [],
      },
      jsFiles: [],
    };
  }

  // ─── Strategy 1: Direct fetch with redirect follow ───
  const crxUrl = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&acceptformat=crx3&x=id%3D${extensionId}%26uc`;

  try {
    console.log('[Scanner] Strategy 1: Direct fetch with redirect follow');
    const response = await fetch(crxUrl, { redirect: 'follow' });
    if (response.ok) {
      const buf = await response.arrayBuffer();
      console.log('[Scanner] Strategy 1 success, size:', buf.byteLength);
      return { source: 'crx', crxData: Array.from(new Uint8Array(buf)), extensionId, needsParsing: true };
    }
    console.warn('[Scanner] Strategy 1 failed: HTTP', response.status);
  } catch (e) {
    console.warn('[Scanner] Strategy 1 failed:', e.message);
  }

  // ─── Strategy 2: Manual redirect — get Location header, then fetch target ───
  try {
    console.log('[Scanner] Strategy 2: Manual redirect follow');
    const redirectResp = await fetch(crxUrl, { redirect: 'manual' });

    // opaqueredirect → browser hid the Location header, try parsing from response URL
    let targetUrl = null;

    if (redirectResp.type === 'opaqueredirect' || redirectResp.status === 0) {
      // Can't read Location from opaque redirect, try with different approach
      console.log('[Scanner] Got opaque redirect, trying strategy 3');
    } else if (redirectResp.status >= 300 && redirectResp.status < 400) {
      targetUrl = redirectResp.headers.get('Location');
      console.log('[Scanner] Redirect target:', targetUrl);
    }

    if (targetUrl) {
      const crxResp = await fetch(targetUrl);
      if (crxResp.ok) {
        const buf = await crxResp.arrayBuffer();
        console.log('[Scanner] Strategy 2 success, size:', buf.byteLength);
        return { source: 'crx', crxData: Array.from(new Uint8Array(buf)), extensionId, needsParsing: true };
      }
    }
  } catch (e) {
    console.warn('[Scanner] Strategy 2 failed:', e.message);
  }

  // ─── Strategy 3: Alternative CRX URL formats ───
  const altUrls = [
    `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=49.0&acceptformat=crx2,crx3&x=id%3D${extensionId}%26uc`,
    `https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x64&os_arch=x86_64&nacl_arch=x86-64&prod=chromecrx&prodchannel=&prodversion=120.0&lang=en&acceptformat=crx3&x=id%3D${extensionId}%26installsource%3Dondemand%26uc`,
  ];

  for (let i = 0; i < altUrls.length; i++) {
    try {
      console.log(`[Scanner] Strategy 3.${i + 1}: Alternative URL`);
      const resp = await fetch(altUrls[i], { redirect: 'follow' });
      if (resp.ok) {
        const buf = await resp.arrayBuffer();
        console.log(`[Scanner] Strategy 3.${i + 1} success, size:`, buf.byteLength);
        return { source: 'crx', crxData: Array.from(new Uint8Array(buf)), extensionId, needsParsing: true };
      }
    } catch (e) {
      console.warn(`[Scanner] Strategy 3.${i + 1} failed:`, e.message);
    }
  }

  // ─── All strategies failed ───
  throw new Error(
    'CRX download failed — Google may be blocking this request. ' +
    'Workaround: Install the extension first, then scan it from the "Installed" tab.'
  );
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
