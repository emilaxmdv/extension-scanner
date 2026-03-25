/**
 * Scan Engine — Combination Rules
 * Detects dangerous multi-factor permission + behaviour combos
 */

import { ESCALATION_RULES } from '../constants.js';
import { isExposureLimited } from '../analyzers/exposure-calculator.js';

export function evaluateEscalationRules({ permissions = [], exposureCategory = 'NO_HOSTS', behavioralIndicators = [], obfuscationScore = 0 }) {
  const triggered = [];
  let total = 0;

  for (const rule of ESCALATION_RULES) {
    const ev = evaluateRule(rule, { permissions, exposureCategory, behavioralIndicators, obfuscationScore });
    if (ev.triggered) {
      triggered.push({ ...rule, evaluation: ev });
      total += rule.score;
    }
  }

  return {
    score: total,
    triggeredRules: triggered,
    ruleCount: triggered.length,
    details: triggered.map(r => ({
      id: r.id,
      description: r.description,
      severity: r.severity,
      score: r.score,
      matchedConditions: r.evaluation.matchedConditions,
    })),
  };
}

function evaluateRule(rule, ctx) {
  const { conditions } = rule;
  const matched = [];
  let allMet = true;

  if (conditions.permissions) {
    const permSet = new Set(ctx.permissions);
    const missing = conditions.permissions.filter(p => !permSet.has(p));
    if (missing.length === 0) matched.push({ type: 'permissions', details: conditions.permissions });
    else allMet = false;
  }

  if (conditions.exposure) {
    if (conditions.exposure.includes(ctx.exposureCategory)) matched.push({ type: 'exposure', details: ctx.exposureCategory });
    else allMet = false;
  }

  if (conditions.exposureLimited !== undefined) {
    const limited = isExposureLimited(ctx.exposureCategory);
    if (conditions.exposureLimited === limited) matched.push({ type: 'exposureLimited', details: limited });
    else allMet = false;
  }

  if (conditions.behaviors) {
    const types = new Set(ctx.behavioralIndicators.map(b => b.type));
    const found = conditions.behaviors.filter(b => types.has(b));
    if (found.length > 0) matched.push({ type: 'behaviors', details: found });
    else allMet = false;
  }

  if (conditions.obfuscation !== undefined) {
    const obf = ctx.obfuscationScore >= 20;
    if (conditions.obfuscation === obf) matched.push({ type: 'obfuscation', details: ctx.obfuscationScore });
    else allMet = false;
  }

  return { triggered: allMet, matchedConditions: matched };
}
