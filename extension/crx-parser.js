/**
 * CRX File Parser — standalone for extension popup context
 * JSZip is loaded locally via script tag in popup.html
 */

window.downloadAndParseCRX = async function(extensionId) {
  const crxUrl = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&acceptformat=crx3&x=id%3D${extensionId}%26uc`;
  const resp = await fetch(crxUrl);
  if (!resp.ok) throw new Error(`Download failed: HTTP ${resp.status}`);
  return window.parseCRXData(new Uint8Array(await resp.arrayBuffer()));
};

window.parseCRXData = async function(uint8) {
  if (!window.JSZip) throw new Error('JSZip not loaded');
  const magic = String.fromCharCode(...uint8.slice(0, 4));
  if (magic !== 'Cr24') throw new Error('Invalid CRX');
  const dv = new DataView(uint8.buffer);
  const ver = dv.getUint32(4, true);
  let zipStart;
  if (ver === 2) zipStart = 16 + dv.getUint32(8, true) + dv.getUint32(12, true);
  else if (ver === 3) zipStart = 12 + dv.getUint32(8, true);
  else throw new Error(`CRX version ${ver} unsupported`);

  const zip = await JSZip.loadAsync(uint8.slice(zipStart));
  const mf = zip.file('manifest.json');
  if (!mf) throw new Error('No manifest.json');
  const manifest = JSON.parse(await mf.async('text'));

  const jsFiles = [];
  const proms = [];
  zip.forEach((p, f) => {
    if (p.endsWith('.js') && !f.dir) {
      proms.push(f.async('text').then(c => jsFiles.push({ name: p, content: c })));
    }
  });
  await Promise.all(proms);

  // Resolve __MSG_*__ i18n names
  let name = manifest.name || 'Unknown';
  if (name.startsWith('__MSG_')) {
    const key = name.replace(/^__MSG_/, '').replace(/__$/, '');
    const locale = manifest.default_locale || 'en';
    const tryPaths = [`_locales/${locale}/messages.json`, '_locales/en/messages.json'];
    for (const p of tryPaths) {
      const f = zip.file(p);
      if (f) {
        try {
          const msgs = JSON.parse(await f.async('text'));
          const match = Object.keys(msgs).find(k => k.toLowerCase() === key.toLowerCase());
          if (match && msgs[match].message) { name = msgs[match].message; break; }
        } catch {}
      }
    }
  }

  return { manifest, jsFiles, name, version: manifest.version };
};
