/**
 * Content Script — Chrome Web Store integration
 * Injects "Scan Security" button on extension detail pages
 */
(function() {
  'use strict';
  if (!location.href.includes('/detail/')) return;

  const ready = document.readyState === 'loading'
    ? new Promise(r => document.addEventListener('DOMContentLoaded', r))
    : Promise.resolve();

  ready.then(init);

  function init() {
    const id = extractId(location.href);
    if (!id) return;
    injectButton(id);
  }

  function extractId(url) {
    // Try with slug first: /detail/slug/ID
    const m1 = url.match(/\/detail\/[^/]+\/([a-z]{32})/i);
    if (m1) return m1[1];
    // New share format: /detail/ID?params
    const m2 = url.match(/\/detail\/([a-z]{32})/i);
    return m2 ? m2[1] : null;
  }

  function injectButton(extensionId) {
    // Try multiple selectors for different Web Store layouts
    const anchor =
      document.querySelector('.webstore-test-button-label') ||
      document.querySelector('[role="button"]') ||
      document.querySelector('header');
    if (!anchor) return;

    const btn = document.createElement('button');
    btn.className = 'ext-scanner-inject-btn';
    btn.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Scan Security
    `;
    btn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'openPopupAndScan', extensionId });
      toast('Opening MalXtension…');
    });

    addCSS();
    anchor.parentElement.insertBefore(btn, anchor.nextSibling);
  }

  function toast(msg) {
    const el = document.createElement('div');
    el.className = 'ext-scanner-toast';
    el.textContent = msg;
    document.body.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 2500);
  }

  function addCSS() {
    if (document.getElementById('ext-scanner-css')) return;
    const s = document.createElement('style');
    s.id = 'ext-scanner-css';
    s.textContent = `
      .ext-scanner-inject-btn {
        display: inline-flex; align-items: center; gap: 7px;
        padding: 10px 18px; margin: 10px 0;
        background: linear-gradient(135deg,#6366f1,#a855f7);
        color: #fff; border: none; border-radius: 8px;
        font-size: 13.5px; font-weight: 600; cursor: pointer;
        box-shadow: 0 2px 10px rgba(99,102,241,.3);
        transition: transform .15s, box-shadow .15s;
      }
      .ext-scanner-inject-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(99,102,241,.4); }
      .ext-scanner-toast {
        position: fixed; top: 20px; right: 20px;
        padding: 14px 22px; background: #1f2937; color: #fff;
        border-radius: 8px; font-size: 13px; font-weight: 500;
        box-shadow: 0 8px 24px rgba(0,0,0,.25); z-index: 999999;
        opacity: 0; transform: translateY(-16px);
        transition: all .25s ease;
      }
      .ext-scanner-toast.show { opacity: 1; transform: none; }
    `;
    document.head.appendChild(s);
  }
})();
