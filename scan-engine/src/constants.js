/**
 * Scan Engine — Constants & Configuration
 * v3.0.0 — Enhanced risk model with CSP analysis & network fingerprinting
 */

// ─── Permission Weights ─────────────────────────────────────
export const PERMISSION_WEIGHTS = {
  // Critical (9-10)
  debugger: 10,
  nativeMessaging: 9,
  webRequestBlocking: 8,

  // High (5-7)
  webRequest: 6,
  scripting: 6,
  cookies: 5,
  proxy: 7,
  vpnProvider: 7,
  platformKeys: 6,
  certificateProvider: 6,

  // Medium (3-4)
  history: 4,
  tabs: 3,
  downloads: 3,
  bookmarks: 2,
  clipboardRead: 3,
  clipboardWrite: 2,
  geolocation: 5,
  management: 4,
  pageCapture: 5,
  tabCapture: 5,
  desktopCapture: 6,
  webNavigation: 3,
  declarativeNetRequest: 4,
  declarativeNetRequestWithHostAccess: 5,
  declarativeNetRequestFeedback: 3,

  // Low (1-2)
  activeTab: 2,
  storage: 2,
  alarms: 1,
  notifications: 1,
  contextMenus: 1,
  declarativeContent: 1,
  idle: 1,
  power: 1,
  system_cpu: 2,
  system_memory: 2,
  system_display: 1,
  tts: 1,
  unlimitedStorage: 2,
  offscreen: 2,
  sidePanel: 1,
};

// ─── Exposure Multipliers ────────────────────────────────────
export const EXPOSURE_MULTIPLIERS = {
  NO_HOSTS: 1.0,
  SINGLE_DOMAIN: 1.0,
  MULTIPLE_DOMAINS: 1.5,
  WILDCARD_SUBDOMAIN: 2.0,
  ALL_URLS: 3.0,
  FILE_ACCESS: 1.8,
};

// ─── Behavioral Weights ──────────────────────────────────────
export const BEHAVIORAL_WEIGHTS = {
  // Code execution (highest)
  EVAL_USAGE: 20,
  FUNCTION_CONSTRUCTOR: 18,
  DYNAMIC_IMPORT: 15,
  WASM_INSTANTIATE: 14,

  // Data exfiltration
  EXTERNAL_FETCH: 12,
  WEBSOCKET_CONNECTION: 14,
  XMLHTTPREQUEST_EXTERNAL: 12,
  SENDBEACON: 13,
  FORM_SUBMIT_EXTERNAL: 10,

  // Cookie/Storage
  DOCUMENT_COOKIE: 10,
  CHROME_COOKIES_API: 8,
  LOCAL_STORAGE_ACCESS: 5,
  INDEXED_DB_ACCESS: 6,

  // Encoding/Decoding
  ATOB_USAGE: 8,
  BTOA_USAGE: 3,
  BASE64_LARGE: 15,
  TEXT_ENCODER_DECODER: 4,

  // DOM manipulation
  INNERHTML_ASSIGNMENT: 7,
  DOCUMENT_WRITE: 8,
  SCRIPT_INJECTION: 15,
  IFRAME_CREATION: 10,
  SHADOW_DOM_CLOSED: 8,

  // Network monitoring
  WEBREQUEST_API: 6,
  WEBREQUEST_BLOCKING: 10,

  // Tab/Script execution
  CHROME_TABS_EXECUTE: 8,
  CHROME_SCRIPTING_EXECUTE: 10,

  // Fingerprinting
  CANVAS_FINGERPRINT: 12,
  WEBGL_FINGERPRINT: 10,
  AUDIO_FINGERPRINT: 10,
  FONT_ENUMERATION: 8,
  SCREEN_ENUMERATION: 6,
  NAVIGATOR_PROPERTIES: 5,

  // Crypto
  CRYPTO_MINING_PATTERN: 20,
  SUBTLE_CRYPTO: 4,

  // Clipboard
  CLIPBOARD_READ_API: 8,
  CLIPBOARD_WRITE_API: 4,
};

// ─── Obfuscation Thresholds ──────────────────────────────────
export const OBFUSCATION_THRESHOLDS = {
  HIGH_ENTROPY: 4.5,
  VERY_HIGH_ENTROPY: 5.0,
  SHORT_VAR_RATIO: 0.6,
  VERY_SHORT_VAR_RATIO: 0.8,
  LARGE_BASE64_SIZE: 500,
  VERY_LARGE_BASE64_SIZE: 2000,
  MIN_CHAR_TO_NEWLINE_RATIO: 200,
  MIN_AVG_LINE_LENGTH: 150,
};

export const OBFUSCATION_SCORES = {
  HIGH_ENTROPY: 10,
  VERY_HIGH_ENTROPY: 15,
  SHORT_VARIABLES: 8,
  VERY_SHORT_VARIABLES: 12,
  LARGE_BASE64: 12,
  VERY_LARGE_BASE64: 20,
  MINIFIED_CODE: 8,
  HEAVY_MINIFICATION: 15,
};

// ─── Escalation Rules (enhanced) ─────────────────────────────
export const ESCALATION_RULES = [
  {
    id: 'COOKIE_EXFILTRATION',
    description: 'Cookie access + wildcard host + cookie API',
    severity: 'critical',
    conditions: {
      permissions: ['cookies'],
      exposure: ['WILDCARD_SUBDOMAIN', 'ALL_URLS'],
      behaviors: ['CHROME_COOKIES_API'],
    },
    score: 25,
  },
  {
    id: 'BLOCKING_INTERCEPT',
    description: 'webRequest blocking + external comms + obfuscation',
    severity: 'critical',
    conditions: {
      permissions: ['webRequestBlocking'],
      behaviors: ['EXTERNAL_FETCH', 'WEBSOCKET_CONNECTION'],
      obfuscation: true,
    },
    score: 30,
  },
  {
    id: 'NATIVE_BRIDGE',
    description: 'Native messaging + external connectivity',
    severity: 'critical',
    conditions: {
      permissions: ['nativeMessaging'],
      behaviors: ['EXTERNAL_FETCH', 'WEBSOCKET_CONNECTION', 'XMLHTTPREQUEST_EXTERNAL'],
    },
    score: 35,
  },
  {
    id: 'EVAL_LIMITED',
    description: 'Code execution without broad host permissions',
    severity: 'medium',
    conditions: {
      behaviors: ['EVAL_USAGE', 'FUNCTION_CONSTRUCTOR'],
      exposureLimited: true,
    },
    score: 10,
  },
  {
    id: 'SCRIPT_INJECTION_WILDCARD',
    description: 'Script injection + broad access',
    severity: 'high',
    conditions: {
      permissions: ['scripting'],
      exposure: ['ALL_URLS', 'WILDCARD_SUBDOMAIN'],
      behaviors: ['CHROME_SCRIPTING_EXECUTE'],
    },
    score: 22,
  },
  {
    id: 'DATA_THEFT',
    description: 'History/cookies + external communication',
    severity: 'critical',
    conditions: {
      permissions: ['history', 'cookies'],
      behaviors: ['EXTERNAL_FETCH'],
      exposure: ['ALL_URLS'],
    },
    score: 20,
  },
  {
    id: 'FINGERPRINT_EXFIL',
    description: 'Browser fingerprinting + data exfiltration',
    severity: 'high',
    conditions: {
      behaviors: ['CANVAS_FINGERPRINT', 'WEBGL_FINGERPRINT', 'EXTERNAL_FETCH'],
    },
    score: 18,
  },
  {
    id: 'STEALTH_COMMS',
    description: 'Obfuscated code + sendBeacon/WebSocket',
    severity: 'high',
    conditions: {
      behaviors: ['SENDBEACON', 'WEBSOCKET_CONNECTION'],
      obfuscation: true,
    },
    score: 20,
  },
  {
    id: 'CRYPTO_MINING',
    description: 'Crypto mining pattern + WASM',
    severity: 'critical',
    conditions: {
      behaviors: ['CRYPTO_MINING_PATTERN', 'WASM_INSTANTIATE'],
    },
    score: 30,
  },
];

// ─── Risk Levels ─────────────────────────────────────────────
export const RISK_LEVELS = {
  LOW: { min: 0, max: 20, label: 'Low' },
  MEDIUM: { min: 21, max: 45, label: 'Medium' },
  HIGH: { min: 46, max: 75, label: 'High' },
  CRITICAL: { min: 76, max: 100, label: 'Critical' },
};

export const MAX_SCORE = 100;
