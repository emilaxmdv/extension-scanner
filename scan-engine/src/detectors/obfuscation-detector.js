/**
 * Scan Engine — Obfuscation Detector
 * Entropy, variable-name, base64, density, and string-encoding analysis
 */

import { parse } from 'acorn';
import { simple as walk } from 'acorn-walk';
import { OBFUSCATION_THRESHOLDS as T, OBFUSCATION_SCORES as S } from '../constants.js';
import { calculateEntropy, analyzeVariableNames, calculateCodeDensity, extractBase64Strings } from '../utils/helpers.js';

export function detectObfuscation(jsFiles) {
  if (!jsFiles || jsFiles.length === 0) {
    return { score: 0, isObfuscated: false, indicators: [], details: {}, summary: [] };
  }
  let total = 0;
  const indicators = [];
  const fileDetails = {};

  for (const f of jsFiles) {
    const r = analyzeFile(f.content, f.name);
    total += r.score;
    indicators.push(...r.indicators);
    fileDetails[f.name] = r;
  }

  const avg = jsFiles.length > 0 ? total / jsFiles.length : 0;
  return {
    score: Math.round(avg),
    isObfuscated: avg >= 20,
    indicators,
    details: fileDetails,
    summary: buildSummary(indicators),
  };
}

function analyzeFile(code, filename) {
  const indicators = [];
  let score = 0;

  // 1. Entropy
  const ent = calculateEntropy(code);
  if (ent >= T.VERY_HIGH_ENTROPY) {
    score += S.VERY_HIGH_ENTROPY;
    indicators.push({ type: 'ENTROPY', score: S.VERY_HIGH_ENTROPY, severity: 'critical', entropy: ent, description: `Very high entropy ${ent.toFixed(2)} bits/char` });
  } else if (ent >= T.HIGH_ENTROPY) {
    score += S.HIGH_ENTROPY;
    indicators.push({ type: 'ENTROPY', score: S.HIGH_ENTROPY, severity: 'high', entropy: ent, description: `High entropy ${ent.toFixed(2)} bits/char` });
  }

  // 2. Variable names
  const ids = extractIdentifiers(code);
  const va = analyzeVariableNames(ids);
  if (va.veryShortRatio >= T.VERY_SHORT_VAR_RATIO) {
    score += S.VERY_SHORT_VARIABLES;
    indicators.push({ type: 'VARIABLES', score: S.VERY_SHORT_VARIABLES, severity: 'high', shortRatio: va.shortRatio, description: `${Math.round(va.shortRatio * 100)}% short variable names` });
  } else if (va.shortRatio >= T.SHORT_VAR_RATIO) {
    score += S.SHORT_VARIABLES;
    indicators.push({ type: 'VARIABLES', score: S.SHORT_VARIABLES, severity: 'medium', shortRatio: va.shortRatio, description: `${Math.round(va.shortRatio * 100)}% short variable names` });
  }

  // 3. Base64
  const b64 = extractBase64Strings(code);
  const large = b64.filter(s => s.length >= T.VERY_LARGE_BASE64_SIZE);
  const medium = b64.filter(s => s.length >= T.LARGE_BASE64_SIZE && s.length < T.VERY_LARGE_BASE64_SIZE);
  if (large.length > 0) {
    score += S.VERY_LARGE_BASE64;
    indicators.push({ type: 'BASE64', score: S.VERY_LARGE_BASE64, severity: 'high', count: b64.length, largeCount: large.length, description: `${large.length} very large base64 string(s)` });
  } else if (medium.length > 0) {
    score += S.LARGE_BASE64;
    indicators.push({ type: 'BASE64', score: S.LARGE_BASE64, severity: 'medium', count: b64.length, description: `${medium.length} large base64 string(s)` });
  }

  // 4. Minification / density
  const d = calculateCodeDensity(code);
  if (d.charsPerLine >= T.MIN_CHAR_TO_NEWLINE_RATIO * 2) {
    score += S.HEAVY_MINIFICATION;
    indicators.push({ type: 'MINIFICATION', score: S.HEAVY_MINIFICATION, severity: 'medium', charsPerLine: Math.round(d.charsPerLine), description: `Heavily minified (${Math.round(d.charsPerLine)} chars/line)` });
  } else if (d.charsPerLine >= T.MIN_CHAR_TO_NEWLINE_RATIO) {
    score += S.MINIFIED_CODE;
    indicators.push({ type: 'MINIFICATION', score: S.MINIFIED_CODE, severity: 'low', charsPerLine: Math.round(d.charsPerLine), description: `Minified code (${Math.round(d.charsPerLine)} chars/line)` });
  }

  // 5. String encoding
  const hex = (code.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
  const uni = (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
  if (hex > 50 || uni > 50) {
    score += 10;
    indicators.push({ type: 'STRING_ENCODING', score: 10, severity: 'medium', hexStrings: hex, unicodeEscapes: uni, description: `${hex} hex + ${uni} unicode escapes` });
  }

  return { score, indicators, filename, metrics: { entropy: ent, variableQuality: va, codeDensity: d } };
}

function extractIdentifiers(code) {
  const ids = [];
  try {
    const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: false });
    walk(ast, { Identifier(n) { if (!BUILTINS.has(n.name)) ids.push(n.name); } });
  } catch {
    const re = /\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g;
    let m;
    while ((m = re.exec(code)) !== null) { if (!BUILTINS.has(m[0])) ids.push(m[0]); }
  }
  return ids;
}

const BUILTINS = new Set([
  'console','window','document','undefined','null','true','false',
  'Array','Object','String','Number','Boolean','Function','Error','Date','Math','JSON',
  'Promise','chrome','browser','Map','Set','Symbol','Proxy','Reflect',
  'parseInt','parseFloat','isNaN','isFinite','setTimeout','setInterval','clearTimeout','clearInterval',
  'require','module','exports','import','export','default','return','if','else','for','while',
  'var','let','const','function','class','new','this','typeof','instanceof','void','delete',
  'try','catch','finally','throw','switch','case','break','continue','do','in','of','with','yield','async','await',
]);

function buildSummary(indicators) {
  const s = [];
  const c = indicators.filter(i => i.severity === 'critical').length;
  const h = indicators.filter(i => i.severity === 'high').length;
  if (c) s.push(`Critical obfuscation: ${c} indicator(s)`);
  if (h) s.push(`High obfuscation: ${h} indicator(s)`);
  return s;
}
