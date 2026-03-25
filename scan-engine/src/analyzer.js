/**
 * Scan Engine — Main Analyzer (Orchestrator)
 * Runs all sub-analyses, computes final risk score, and builds the report
 */

import { calculateCapabilityScore, extractHostPermissions } from './analyzers/capability-scorer.js';
import { calculateExposureMultiplier, calculateExposureScore } from './analyzers/exposure-calculator.js';
import { detectBehavioralIndicators } from './detectors/behavioral-detector.js';
import { detectObfuscation } from './detectors/obfuscation-detector.js';
import { evaluateEscalationRules } from './analyzers/combination-rules.js';
import { MAX_SCORE, RISK_LEVELS } from './constants.js';
import { cap, getRiskLevel } from './utils/helpers.js';

/**
 * Full extension analysis
 * @param {Object} manifest   — parsed manifest.json
 * @param {Array<{name:string, content:string}>} jsFiles
 * @returns {Object}
 */
export async function analyzeExtension(manifest, jsFiles = []) {
  if (!manifest) throw new Error('manifest is required');
  if (!Array.isArray(jsFiles)) throw new Error('jsFiles must be an array');

  const t0 = performance.now();

  // 1–5 — run sub-analyses
  const capResult   = calculateCapabilityScore(manifest);
  const hosts       = extractHostPermissions(manifest);
  const expResult   = calculateExposureMultiplier(hosts);
  const behResult   = detectBehavioralIndicators(jsFiles);
  const obfResult   = detectObfuscation(jsFiles);
  const escResult   = evaluateEscalationRules({
    permissions: capResult.permissions,
    exposureCategory: expResult.category,
    behavioralIndicators: behResult.indicators,
    obfuscationScore: obfResult.score,
  });

  // 6 — final score
  const raw = (capResult.score * expResult.multiplier) + behResult.score + obfResult.score + escResult.score;
  const score = cap(Math.round(raw), MAX_SCORE);
  const level = getRiskLevel(score, RISK_LEVELS);

  const elapsed = Math.round(performance.now() - t0);

  return {
    score,
    level,
    breakdown: {
      capability: capResult.score,
      exposure: Math.round(calculateExposureScore(capResult.score, expResult.multiplier)),
      behavior: behResult.score,
      obfuscation: obfResult.score,
      combinations: escResult.score,
    },
    details: {
      capability: { score: capResult.score, permissions: capResult.permissions, highRiskPermissions: capResult.highRiskPermissions, permissionDetails: capResult.details },
      exposure: { multiplier: expResult.multiplier, category: expResult.category, hostPermissions: hosts, analysis: expResult.analysis },
      behavioral: { score: behResult.score, indicators: behResult.indicators, summary: behResult.summary },
      obfuscation: { score: obfResult.score, isObfuscated: obfResult.isObfuscated, indicators: obfResult.indicators, summary: obfResult.summary },
      escalation: { score: escResult.score, triggeredRules: escResult.details, ruleCount: escResult.ruleCount },
    },
    summary: buildSummary({ score, level, capResult, expResult, behResult, obfResult, escResult }),
    metadata: {
      manifestVersion: manifest.manifest_version || 2,
      extensionName: manifest.name || 'Unknown',
      extensionVersion: manifest.version || 'Unknown',
      filesAnalyzed: jsFiles.length,
      analysisDate: new Date().toISOString(),
      analysisDuration: elapsed,
    },
  };
}

/**
 * Quick scan — lightweight subset of results
 */
export async function quickScan(manifest, jsFiles = []) {
  const full = await analyzeExtension(manifest, jsFiles);
  return {
    score: full.score,
    level: full.level,
    highRiskPermissions: full.details.capability.highRiskPermissions,
    isObfuscated: full.details.obfuscation.isObfuscated,
    hasDangerousCombinations: full.details.escalation.ruleCount > 0,
    concerns: full.summary.concerns,
    duration: full.metadata.analysisDuration,
  };
}

/**
 * Export results as formatted JSON string
 */
export function exportResults(results, includeDetails = true) {
  const out = { score: results.score, level: results.level, breakdown: results.breakdown, summary: results.summary, metadata: results.metadata };
  if (includeDetails) out.details = results.details;
  return JSON.stringify(out, null, 2);
}

// ─── Internal helpers ────────────────────────────────────────
function buildSummary({ score, level, capResult, expResult, behResult, obfResult, escResult }) {
  const s = { riskLevel: level, score, keyFindings: [], recommendations: [], concerns: [] };

  if (capResult.highRiskPermissions.length > 0) {
    s.keyFindings.push(`${capResult.highRiskPermissions.length} high-risk permission(s): ${capResult.highRiskPermissions.join(', ')}`);
  }
  if (expResult.category === 'ALL_URLS') s.concerns.push('Extension has access to ALL websites');
  else if (expResult.category === 'WILDCARD_SUBDOMAIN') s.concerns.push('Uses wildcard host permissions');

  if (behResult.summary.length) s.concerns.push(...behResult.summary);
  if (obfResult.isObfuscated) s.concerns.push('Code appears obfuscated');
  if (escResult.ruleCount > 0) s.concerns.push(`${escResult.ruleCount} dangerous permission combination(s)`);

  // Recommendations
  if (level === 'Critical' || level === 'High') {
    s.recommendations.push('Exercise extreme caution — consider alternatives');
    s.recommendations.push('Review all permissions and code carefully');
  } else if (level === 'Medium') {
    s.recommendations.push('Review extension permissions before installing');
    s.recommendations.push('Monitor behaviour after installation');
  } else {
    s.recommendations.push('Extension appears to have minimal risk');
  }

  return s;
}
