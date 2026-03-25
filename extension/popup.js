/**
 * Extension Scanner — Popup Controller
 * Uses the bundled ScanEngine for full AST-based analysis
 */

// ═══════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════
let currentExtensions = [];
let currentAnalysis = null;
let scanHistory = [];

// ═══════════════════════════════════════════════════════════════
//  DOM references
// ═══════════════════════════════════════════════════════════════
const $ = (s, p = document) => p.querySelector(s);
const $$ = (s, p = document) => [...p.querySelectorAll(s)];

const el = {
  tabs:        $$('.tab'),
  panels:      $$('.panel'),
  scanInput:   $('#scan-input'),
  scanBtn:     $('#scan-btn'),
  chips:       $$('.chip'),
  refreshBtn:  $('#refresh-btn'),
  extList:     $('#ext-list'),
  historyList: $('#history-list'),
  // results
  results:      $('#results'),
  resName:      $('#res-name'),
  closeResults: $('#close-results'),
  scoreNum:     $('#score-num'),
  ringProgress: $('#ring-progress'),
  levelBadge:   $('#level-badge'),
  riskDesc:     $('#risk-desc'),
  scanTime:     $('#scan-time'),
  bars:         $('#bars'),
  concernsCard: $('#concerns-card'),
  concernsUl:   $('#concerns-ul'),
  escalationCard: $('#escalation-card'),
  escalationList: $('#escalation-list'),
  permsCard:    $('#perms-card'),
  permsBadges:  $('#perms-badges'),
  behaviorCard: $('#behavior-card'),
  behaviorTable:$('#behavior-table'),
  recsUl:       $('#recs-ul'),
  exportBtn:    $('#export-btn'),
  copyBtn:      $('#copy-btn'),
  // loading
  loading:     $('#loading'),
  loadingMsg:  $('#loading-msg'),
  loadingSteps:$('#loading-steps'),
};

// ═══════════════════════════════════════════════════════════════
//  Init
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initScan();
  initInstalled();
  initResults();
  loadHistory();
});

// ═══════════════════════════════════════════════════════════════
//  Tabs
// ═══════════════════════════════════════════════════════════════
function initTabs() {
  el.tabs.forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));
}
function switchTab(name) {
  el.tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  el.panels.forEach(p => p.classList.toggle('active', p.id === `panel-${name}`));
  if (name === 'installed') loadInstalledExtensions();
  if (name === 'history') renderHistory();
}

// ═══════════════════════════════════════════════════════════════
//  Scan panel
// ═══════════════════════════════════════════════════════════════
function initScan() {
  el.scanBtn.addEventListener('click', handleScan);
  el.scanInput.addEventListener('keydown', e => { if (e.key === 'Enter') handleScan(); });
  el.chips.forEach(c => c.addEventListener('click', () => {
    el.scanInput.value = c.dataset.id;
    handleScan();
  }));
}

async function handleScan() {
  const raw = el.scanInput.value.trim();
  if (!raw) return notify('Enter a URL or extension ID');
  const id = extractId(raw);
  if (!id) return notify('Invalid URL or ID');
  await runScan(id);
}

function extractId(input) {
  input = input.trim();
  const pats = [
    // Old format: chrome.google.com/webstore/detail/name-slug/ID
    /chrome\.google\.com\/webstore\/detail\/[^/]+\/([a-z]{32})/i,
    // New format with slug: chromewebstore.google.com/detail/name-slug/ID
    /chromewebstore\.google\.com\/detail\/[^/]+\/([a-z]{32})/i,
    // New share format (no slug): chromewebstore.google.com/detail/ID
    /chromewebstore\.google\.com\/detail\/([a-z]{32})/i,
    // Bare ID (with or without query params)
    /^([a-z]{32})(\?.*)?$/i,
  ];
  for (const p of pats) { const m = input.match(p); if (m) return m[1]; }
  return null;
}

// ═══════════════════════════════════════════════════════════════
//  Installed panel
// ═══════════════════════════════════════════════════════════════
function initInstalled() {
  el.refreshBtn.addEventListener('click', loadInstalledExtensions);
}

async function loadInstalledExtensions() {
  el.extList.innerHTML = '<div class="loader"><div class="spinner"></div><span>Loading…</span></div>';
  try {
    const resp = await chrome.runtime.sendMessage({ action: 'getInstalledExtensions' });
    if (!resp.success) throw new Error(resp.error);
    currentExtensions = resp.data;
    renderExtList();
  } catch (e) {
    el.extList.innerHTML = `<p class="empty-state">Could not load extensions</p>`;
  }
}

function renderExtList() {
  if (!currentExtensions.length) {
    el.extList.innerHTML = '<p class="empty-state">No extensions found</p>';
    return;
  }
  el.extList.innerHTML = currentExtensions.map(ext => `
    <div class="ext-card" data-id="${ext.id}">
      <img src="${ext.icons?.[0]?.url || 'icons/icon48.png'}" class="ext-icon" onerror="this.src='icons/icon48.png'" alt="">
      <div class="ext-info">
        <span class="ext-name">${esc(ext.name)}</span>
        <span class="ext-ver">v${ext.version}</span>
      </div>
      <button class="btn btn-primary btn-sm scan-ext-btn" data-id="${ext.id}">Scan</button>
    </div>
  `).join('');
  $$('.scan-ext-btn').forEach(b => b.addEventListener('click', () => scanInstalledExt(b.dataset.id)));
}

async function scanInstalledExt(id) {
  const ext = currentExtensions.find(e => e.id === id);
  if (!ext) return;
  showLoading(`Analysing ${ext.name}…`);
  try {
    const manifest = {
      manifest_version: 3,
      name: ext.name,
      version: ext.version,
      permissions: ext.permissions || [],
      host_permissions: ext.hostPermissions || [],
    };
    addStep('Running full analysis engine…');
    const results = await ScanEngine.analyzeExtension(manifest, []);
    currentAnalysis = results;
    displayResults(ext.name, results);
    saveToHistory(ext.name, results);
  } catch (e) {
    notify(`Analysis failed: ${e.message}`);
  } finally {
    hideLoading();
  }
}

// ═══════════════════════════════════════════════════════════════
//  CRX Scan (Web Store)
// ═══════════════════════════════════════════════════════════════
async function runScan(extensionId) {
  showLoading('Fetching extension…');
  try {
    const resp = await chrome.runtime.sendMessage({ action: 'fetchWebStoreExtension', extensionId });
    if (!resp.success) throw new Error(resp.error);

    let manifest, jsFiles, name;

    if (resp.data.needsParsing) {
      addStep('Downloading CRX file…');
      const bytes = new Uint8Array(resp.data.crxData);
      addStep('Extracting extension files…');
      const parsed = await parseCRXDataInline(bytes);
      manifest = parsed.manifest;
      jsFiles  = parsed.jsFiles;
      name     = parsed.name;
    } else {
      manifest = resp.data.manifest;
      jsFiles  = resp.data.jsFiles || [];
      name     = resp.data.name || manifest.name;
    }

    addStep(`Running AST analysis on ${jsFiles.length} file(s)…`);
    const results = await ScanEngine.analyzeExtension(manifest, jsFiles);
    currentAnalysis = results;
    displayResults(name, results);
    saveToHistory(name, results);
  } catch (e) {
    notify(`Scan failed: ${e.message}`);
  } finally {
    hideLoading();
  }
}

// ═══════════════════════════════════════════════════════════════
//  CRX Parser (inline, uses JSZip)
// ═══════════════════════════════════════════════════════════════
async function parseCRXDataInline(uint8) {
  const magic = String.fromCharCode(...uint8.slice(0, 4));
  if (magic !== 'Cr24') throw new Error('Invalid CRX file');
  const dv = new DataView(uint8.buffer);
  const ver = dv.getUint32(4, true);
  let zipStart;
  if (ver === 2) {
    zipStart = 16 + dv.getUint32(8, true) + dv.getUint32(12, true);
  } else if (ver === 3) {
    zipStart = 12 + dv.getUint32(8, true);
  } else throw new Error(`Unsupported CRX version: ${ver}`);

  const zip = await JSZip.loadAsync(uint8.slice(zipStart));
  const mf = zip.file('manifest.json');
  if (!mf) throw new Error('manifest.json not found');
  const manifest = JSON.parse(await mf.async('text'));

  const jsFiles = [];
  const promises = [];
  zip.forEach((path, file) => {
    if (path.endsWith('.js') && !file.dir) {
      promises.push(file.async('text').then(content => jsFiles.push({ name: path, content })));
    }
  });
  await Promise.all(promises);

  // Resolve __MSG_*__ i18n placeholders from _locales
  let name = manifest.name || 'Unknown';
  if (name.startsWith('__MSG_')) {
    name = await resolveI18n(zip, name) || name;
  }

  return { manifest, jsFiles, name };
}

/**
 * Resolve __MSG_key__ placeholders using _locales/en/messages.json (fallback: default_locale or first found)
 */
async function resolveI18n(zip, msgKey) {
  const key = msgKey.replace(/^__MSG_/, '').replace(/__$/, '');

  // Try default_locale first, then 'en', then any locale found
  const tryLocales = ['en', 'en_US', 'en_GB'];

  // Check manifest for default_locale
  try {
    const mf = zip.file('manifest.json');
    if (mf) {
      const m = JSON.parse(await mf.async('text'));
      if (m.default_locale) tryLocales.unshift(m.default_locale);
    }
  } catch {}

  for (const locale of tryLocales) {
    const path = `_locales/${locale}/messages.json`;
    const file = zip.file(path);
    if (file) {
      try {
        const messages = JSON.parse(await file.async('text'));
        // Keys in messages.json are case-insensitive
        const match = Object.keys(messages).find(k => k.toLowerCase() === key.toLowerCase());
        if (match && messages[match].message) {
          return messages[match].message;
        }
      } catch {}
    }
  }

  // Last resort: try any _locales/*/messages.json
  let found = null;
  zip.forEach((path, file) => {
    if (!found && path.match(/^_locales\/[^/]+\/messages\.json$/)) {
      found = file;
    }
  });
  if (found) {
    try {
      const messages = JSON.parse(await found.async('text'));
      const match = Object.keys(messages).find(k => k.toLowerCase() === key.toLowerCase());
      if (match && messages[match].message) return messages[match].message;
    } catch {}
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════
//  Display Results
// ═══════════════════════════════════════════════════════════════
function initResults() {
  el.closeResults.addEventListener('click', () => el.results.classList.add('hidden'));
  el.exportBtn.addEventListener('click', exportJSON);
  el.copyBtn.addEventListener('click', copyJSON);
}

function displayResults(name, r) {
  el.resName.textContent = name;

  // Score ring animation
  animateScore(r.score, r.level);

  // Level badge
  el.levelBadge.textContent = r.level;
  el.levelBadge.className = 'level-badge ' + r.level.toLowerCase();

  // Risk description
  el.riskDesc.textContent = riskText(r.level, r.score);

  // Scan time
  el.scanTime.textContent = r.metadata.analysisDuration
    ? `Analysed ${r.metadata.filesAnalyzed} file(s) in ${r.metadata.analysisDuration}ms`
    : `${r.metadata.filesAnalyzed} file(s) analysed`;

  // Breakdown bars
  renderBars(r.breakdown);

  // Concerns
  const concerns = r.summary?.concerns || [];
  toggle(el.concernsCard, concerns.length > 0);
  el.concernsUl.innerHTML = concerns.map(c => `<li>${esc(c)}</li>`).join('');

  // Escalation rules
  const esc_rules = r.details?.escalation?.triggeredRules || [];
  toggle(el.escalationCard, esc_rules.length > 0);
  el.escalationList.innerHTML = esc_rules.map(rule => `
    <div class="esc-rule ${rule.severity || 'high'}">
      <div class="esc-header">
        <span class="esc-id">${esc(rule.id)}</span>
        <span class="esc-score">+${rule.score}</span>
      </div>
      <p class="esc-desc">${esc(rule.description)}</p>
    </div>
  `).join('');

  // Permissions
  const hrp = r.details?.capability?.highRiskPermissions || [];
  toggle(el.permsCard, hrp.length > 0);
  el.permsBadges.innerHTML = hrp.map(p => `<span class="perm-badge">${esc(p)}</span>`).join('');

  // Behavioral indicators
  const indicators = (r.details?.behavioral?.indicators || []).filter(i => i.count > 0);
  toggle(el.behaviorCard, indicators.length > 0);
  if (indicators.length > 0) {
    indicators.sort((a, b) => b.score - a.score);
    el.behaviorTable.innerHTML = `
      <div class="beh-header"><span>Pattern</span><span>Count</span><span>Weight</span><span>Score</span></div>
      ${indicators.slice(0, 15).map(i => `
        <div class="beh-row ${i.weight >= 15 ? 'critical' : i.weight >= 10 ? 'high' : ''}">
          <span class="beh-type">${formatType(i.type)}</span>
          <span class="beh-count">${i.count}</span>
          <span class="beh-weight">${i.weight}</span>
          <span class="beh-score">${i.score}</span>
        </div>
      `).join('')}
    `;
  }

  // Recommendations
  const recs = r.summary?.recommendations || [];
  el.recsUl.innerHTML = recs.map(r => `<li>${esc(r)}</li>`).join('');

  el.results.classList.remove('hidden');
}

function animateScore(score, level) {
  const circ = 326.73; // 2π×52
  const target = circ - (score / 100) * circ;
  const colors = { low: '#10b981', medium: '#f59e0b', high: '#a855f7', critical: '#ef4444' };
  el.ringProgress.style.stroke = colors[level.toLowerCase()] || '#6366f1';

  // Animate offset
  let current = circ;
  el.ringProgress.style.strokeDashoffset = circ;
  el.scoreNum.textContent = '0';

  const start = performance.now();
  const dur = 800;
  function tick(now) {
    const t = Math.min((now - start) / dur, 1);
    const ease = 1 - Math.pow(1 - t, 3); // easeOutCubic
    el.ringProgress.style.strokeDashoffset = circ - ease * (circ - target);
    el.scoreNum.textContent = Math.round(ease * score);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderBars(bd) {
  const max = 50;
  const labels = {
    capability: { icon: '🔑', label: 'Capability' },
    exposure:   { icon: '🌐', label: 'Exposure' },
    behavior:   { icon: '⚡', label: 'Behavior' },
    obfuscation:{ icon: '🔒', label: 'Obfuscation' },
    combinations:{ icon: '💥', label: 'Combinations' },
  };
  el.bars.innerHTML = Object.entries(bd).map(([k, v]) => {
    const pct = Math.min((v / max) * 100, 100);
    const { icon, label } = labels[k] || { icon: '•', label: k };
    return `
      <div class="bar-row">
        <span class="bar-label">${icon} ${label}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <span class="bar-val">${v}</span>
      </div>`;
  }).join('');
}

function riskText(level) {
  const m = {
    Low: 'Minimal security risk. Basic permissions with no concerning patterns.',
    Medium: 'Moderate risk. Review permissions and concerns before installing.',
    High: 'Significant security risks detected. Careful review recommended.',
    Critical: 'Critical security risks. Exercise extreme caution.',
  };
  return m[level] || '';
}

// ═══════════════════════════════════════════════════════════════
//  History
// ═══════════════════════════════════════════════════════════════
function saveToHistory(name, results) {
  scanHistory.unshift({
    name,
    score: results.score,
    level: results.level,
    date: new Date().toISOString(),
    files: results.metadata.filesAnalyzed,
  });
  if (scanHistory.length > 50) scanHistory.length = 50;
  chrome.storage.local.set({ scanHistory });
}

function loadHistory() {
  chrome.storage.local.get(['scanHistory'], r => {
    scanHistory = r.scanHistory || [];
  });
}

function renderHistory() {
  if (!scanHistory.length) {
    el.historyList.innerHTML = '<p class="empty-state">No scans yet.</p>';
    return;
  }
  el.historyList.innerHTML = scanHistory.map(h => `
    <div class="history-item">
      <div class="history-info">
        <span class="history-name">${esc(h.name)}</span>
        <span class="history-date">${new Date(h.date).toLocaleDateString()}</span>
      </div>
      <span class="level-badge sm ${h.level.toLowerCase()}">${h.score} · ${h.level}</span>
    </div>
  `).join('');
}

// ═══════════════════════════════════════════════════════════════
//  Export
// ═══════════════════════════════════════════════════════════════
function exportJSON() {
  if (!currentAnalysis) return;
  const json = ScanEngine.exportResults(currentAnalysis);
  const blob = new Blob([json], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan-${currentAnalysis.metadata.extensionName}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function copyJSON() {
  if (!currentAnalysis) return;
  navigator.clipboard.writeText(ScanEngine.exportResults(currentAnalysis)).then(() => {
    el.copyBtn.textContent = 'Copied!';
    setTimeout(() => { el.copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy'; }, 1500);
  });
}

// ═══════════════════════════════════════════════════════════════
//  Loading overlay
// ═══════════════════════════════════════════════════════════════
function showLoading(msg) {
  el.loadingMsg.textContent = msg;
  el.loadingSteps.innerHTML = '';
  el.loading.classList.remove('hidden');
}
function addStep(msg) {
  el.loadingSteps.insertAdjacentHTML('beforeend', `<div class="step"><span class="step-dot">✓</span>${esc(msg)}</div>`);
}
function hideLoading() {
  el.loading.classList.add('hidden');
}

// ═══════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function toggle(el, show) { el.classList.toggle('hidden', !show); }
function formatType(t) { return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()); }
function notify(msg) {
  // Remove any existing toast
  const old = document.querySelector('.toast');
  if (old) old.remove();

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <div class="toast-msg">${esc(msg)}</div>
    <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
  `;
  document.querySelector('.app').appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 6000);
}
