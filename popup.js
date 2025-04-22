document.addEventListener('DOMContentLoaded', () => {
  chrome.runtime.sendMessage({ type: 'getScanResults' }, (response) => {
    const container = document.getElementById('results');
    container.innerHTML = ''; 
    response.results.forEach(result => {
      const div = document.createElement('div');
      div.className = 'extension';

      const riskClass = result.score >= 7 ? 'high' : result.score >= 4 ? 'moderate' : 'safe';

      div.innerHTML = `
        <div class="extension-name">${result.name}</div>
        <div class="${riskClass}">Risk Score: ${result.score}</div>
        <button class="toggle-notes">Show Notes</button>
        <ul class="notes" style="display:none;">
          ${result.notes.map(n => `<li>${n}</li>`).join('')}
        </ul>
      `;

      const button = div.querySelector('.toggle-notes');
      const notes = div.querySelector('.notes');
      button.addEventListener('click', () => {
        notes.style.display = notes.style.display === 'none' ? 'block' : 'none';
        button.textContent = notes.style.display === 'none' ? 'Show Notes' : 'Hide Notes';
      });

      container.appendChild(div);
    });
  });
});
