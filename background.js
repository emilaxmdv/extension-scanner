let rules = null;

fetch(chrome.runtime.getURL('rules.json'))
  .then(response => response.json())
  .then(data => {
    rules = data;
  })
  .catch(error => console.error('Error loading rules:', error));

chrome.runtime.onInstalled.addListener(() => {
  scanExtensions();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getScanResults') {
    const waitForRules = () => {
      if (rules) {
        scanExtensions().then(results => sendResponse({ results }));
      } else {
        setTimeout(waitForRules, 100);
      }
    };
    waitForRules();
    return true; // Keep message channel open for async response
  }
});

async function scanExtensions() {
  const extensions = await chrome.management.getAll();
  const results = extensions
    .filter(ext => ext.type === 'extension' && ext.id !== chrome.runtime.id)
    .map(ext => {
      let score = 0;
      const notes = [];

      if (ext.permissions?.includes('tabs')) {
        score += 2;
        notes.push('Uses tabs permission');
      }

      if (ext.permissions?.includes('clipboardRead') || ext.permissions?.includes('clipboardWrite')) {
        score += 2;
        notes.push('Accesses clipboard');
      }

      if (ext.hostPermissions?.some(p => rules?.high_risk_hosts?.includes(p))) {
        score += 5;
        notes.push('Can access all URLs');
      }

      if (['sideload', 'development'].includes(ext.installType)) {
        score += 2;
        notes.push('Sideloaded or developer mode');
      }

      if (rules?.keywords) {
        for (const k of rules.keywords) {
          if (ext.description?.toLowerCase().includes(k.pattern)) {
            score += k.score;
            notes.push(`Suspicious keyword in description: ${k.note}`);
          }
        }
      }

      return {
        name: ext.name,
        id: ext.id,
        description: ext.description || '',
        score,
        notes
      };
    });

  return results;
}
