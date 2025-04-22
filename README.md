🔍 Extension Scanner

A Chrome Extension that scans installed browser extensions to detect potential risks based on permissions, host access, install type, and suspicious keywords.

## ⚙️ Features

- ✅ Analyzes all installed extensions (excluding itself)
- 🚨 Flags extensions with high-risk permissions or hosts
- 🔑 Detects suspicious keywords in descriptions (e.g., "keylogger", "spyware", "crypto")
- 📊 Calculates a "Risk Score" for each extension
- 🌐 Displays human-readable scan results in the popup
- 🎨 Color-coded risk indicators (Green: Safe, Yellow: Moderate, Red: High Risk)
- 🔄 Auto-loads rules from a `rules.json` file
- 🧩 Works with Chrome and Chromium-based browsers

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/emilaxmdv/extension-scanner.git
cd extension-scanner
```

### 2. Load the extension in Chrome

1. Open Google Chrome
2. Navigate to `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked**
5. Select the cloned `extension-scanner` folder

---

## 🛠️ Improving Detection Capabilities

### 🔑 Add More Keywords

Edit `rules.json` and include additional keywords to expand detection capabilities:

```json
{
  "pattern": "autofill",
  "score": 3,
  "note": "May be used for credential theft"
}
```

### 🌍 Expand High-Risk Hosts

Add specific domains or patterns to `high_risk_hosts` in `rules.json` for more granular control.

### 🤖 Use AI/LLM Integration (Future Scope)

You could enhance the extension by:

- Connecting it to an LLM via API (like OpenAI) to auto-analyze extension descriptions
- Creating a backend that regularly updates the rules based on new threat intelligence

### 🧪 Cross-Platform Support

- Works with **Chrome**, **Edge**, **Brave**, and any Chromium-based browser that supports the `chrome.management` API.
- Firefox support would require adapting to `browser.management` API.

---

## 📂 Project Structure

```
extension-scanner/
│
├── manifest.json        # Chrome extension manifest
├── background.js        # Scans installed extensions in the background
├── popup.html           # Popup UI
├── popup.js             # Handles popup logic and UI updates
├── rules.json           # Contains detection rules (keywords, host patterns)
├── icons/               # Extension icons
└── README.md            # This file
```
