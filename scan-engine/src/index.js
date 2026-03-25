/**
 * Scan Engine — Public API
 * Import this file for library usage, or bundle for browser
 *
 *   import { analyzeExtension, quickScan, exportResults } from 'scan-engine';
 *   const report = await analyzeExtension(manifest, jsFiles);
 */

export { analyzeExtension, quickScan, exportResults } from './analyzer.js';
export { calculateCapabilityScore, extractHostPermissions, getPermissionDescriptions } from './analyzers/capability-scorer.js';
export { calculateExposureMultiplier, getExposureDescription, isExposureLimited } from './analyzers/exposure-calculator.js';
export { detectBehavioralIndicators } from './detectors/behavioral-detector.js';
export { detectObfuscation } from './detectors/obfuscation-detector.js';
export { evaluateEscalationRules } from './analyzers/combination-rules.js';
export { PERMISSION_WEIGHTS, BEHAVIORAL_WEIGHTS, RISK_LEVELS, MAX_SCORE } from './constants.js';
