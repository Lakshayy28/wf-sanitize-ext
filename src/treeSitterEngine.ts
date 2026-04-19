/**
 * treeSitterEngine.ts — Tree-Sitter CST Verification Engine
 * ═════════════════════════════════════════════════════════
 * Loads WASM grammars for JSON, YAML, TOML.
 * Used as a VERIFIER: after Gitleaks scans raw text and finds secrets,
 * Tree-Sitter confirms each finding falls inside a value node (not a key
 * or structural element). This preserves 100% of Gitleaks' context while
 * adding 100% of Tree-Sitter's structural precision.
 */

import * as path from 'path';
import * as fs from 'fs';

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

export type SupportedLang = 'json' | 'yaml' | 'toml' | 'html' | 'bash' | 'ini';

export interface ValueNode {
  text: string;
  startIndex: number;
  endIndex: number;
}

// web-tree-sitter@0.24.x: default export is the Parser constructor,
// Language is Parser.Language, node type is Parser.SyntaxNode
type ParserCtor = typeof import('web-tree-sitter');
type SyntaxNode = import('web-tree-sitter').SyntaxNode;

// ────────────────────────────────────────────────────────────────────────────
// State — Parser & Grammar Cache
// ────────────────────────────────────────────────────────────────────────────

let Parser: ParserCtor | null = null;
const grammarCache = new Map<string, import('web-tree-sitter').Language>();
let extensionBasePath = '';

// ────────────────────────────────────────────────────────────────────────────
// Initialization
// ────────────────────────────────────────────────────────────────────────────

/**
 * Initialize the Tree-Sitter WASM runtime. Must be called once at activation.
 * @param extPath - The VS Code extension's install path (context.extensionPath)
 */
export async function initTreeSitter(extPath: string): Promise<void> {
  extensionBasePath = extPath;

  if (Parser) { return; } // Already initialized

  const P: ParserCtor = require('web-tree-sitter');

  const grammarsDir = path.join(extPath, 'grammars');

  await P.init({
    locateFile: (file: string) => path.join(grammarsDir, file),
  });

  Parser = P;
}

/**
 * Load a language grammar WASM. Cached after first load.
 */
async function loadGrammar(lang: string): Promise<import('web-tree-sitter').Language> {
  const cached = grammarCache.get(lang);
  if (cached) { return cached; }

  if (!Parser) {
    throw new Error('[SafeChat] Tree-Sitter not initialized. Call initTreeSitter() first.');
  }

  const wasmFile = `tree-sitter-${lang}.wasm`;
  const wasmPath = path.join(extensionBasePath, 'grammars', wasmFile);

  if (!fs.existsSync(wasmPath)) {
    throw new Error(`[SafeChat] Grammar WASM not found: ${wasmPath}`);
  }

  const language = await Parser.Language.load(wasmPath);
  grammarCache.set(lang, language);
  return language;
}

// ────────────────────────────────────────────────────────────────────────────
// CST Parsing
// ────────────────────────────────────────────────────────────────────────────

/**
 * Parse text into a CST using the specified grammar.
 * Returns null if parsing fails or lang is 'ini' (uses custom verifier).
 * Creates a fresh Parser per call for concurrency safety.
 */
export async function parseCST(text: string, lang: SupportedLang): Promise<import('web-tree-sitter').Tree | null> {
  if (!Parser) {
    throw new Error('[SafeChat] Tree-Sitter not initialized. Call initTreeSitter() first.');
  }

  // INI has no WASM grammar — uses custom regex-based verifier
  if (lang === 'ini') { return null; }

  const grammar = await loadGrammar(lang);
  const parser = new Parser();  // Fresh instance: no shared mutable state
  parser.setLanguage(grammar);
  const tree = parser.parse(text);
  parser.delete();  // Tree is independent; parser can be freed
  return tree;
}

// ────────────────────────────────────────────────────────────────────────────
// Two-Pass Verification — Gitleaks Finding Verifier
// ────────────────────────────────────────────────────────────────────────────

import { lineColToByteOffset, byteOffsetToCharIndex, type GitleaksFinding } from './gitleaksEngine';

/**
 * Checks whether a byte range [startIndex, endIndex) falls inside a VALUE
 * node in the CST (not a key, property name, section header, or structure).
 *
 * Uses `descendantForIndex` to find the deepest node spanning the range,
 * then walks UP via `.parent` to determine structural context per grammar.
 *
 * Fail-closed: returns `true` (mask it) when context is ambiguous or ERROR.
 */
export function verifyFindingIsValueNode(
  root: SyntaxNode,
  lang: SupportedLang,
  startIndex: number,
  endIndex: number,
): boolean {
  // descendantForIndex uses inclusive end, so subtract 1
  const node = root.descendantForIndex(startIndex, Math.max(startIndex, endIndex - 1));

  if (!node) { return true; } // fail-closed

  switch (lang) {
    case 'json':
      return isJsonValuePosition(node, startIndex, endIndex);
    case 'yaml':
      return isYamlValuePosition(node, startIndex, endIndex);
    case 'toml':
      return isTomlValuePosition(node, startIndex, endIndex);
    case 'html':
      return isXmlValuePosition(node, startIndex, endIndex);
    case 'bash':
      return isEnvValuePosition(node, startIndex, endIndex);
    default:
      return true; // unknown lang or 'ini' → fail-closed
  }
}

// ── JSON: Is the node inside a pair's value (not key)? ─────────────────────

function isJsonValuePosition(node: SyntaxNode, start: number, end: number): boolean {
  let current: SyntaxNode | null = node;

  while (current) {
    if (current.type === 'ERROR') { return true; } // fail-closed
    if (current.type === 'comment') { return true; } // mask secrets in comments

    if (current.type === 'pair') {
      const keyNode = current.childForFieldName('key');
      // If the secret is entirely within the key node → it's a key, reject
      if (keyNode && start >= keyNode.startIndex && end <= keyNode.endIndex) {
        return false;
      }
      // Otherwise it's in the value side (or spans key+value) → accept
      return true;
    }

    // Array elements are always values
    if (current.type === 'array') {
      return true;
    }

    current = current.parent;
  }

  // Reached root without finding pair/array — structural/top-level → accept (fail-closed)
  return true;
}

// ── YAML: Is the node inside a mapping pair's value (not key)? ─────────────

function isYamlValuePosition(node: SyntaxNode, start: number, end: number): boolean {
  let current: SyntaxNode | null = node;

  while (current) {
    if (current.type === 'ERROR') { return true; } // fail-closed
    if (current.type === 'comment') { return true; } // mask secrets in comments

    if (current.type === 'block_mapping_pair' || current.type === 'flow_pair') {
      const keyNode = current.childForFieldName('key');
      if (keyNode && start >= keyNode.startIndex && end <= keyNode.endIndex) {
        return false;
      }
      return true;
    }

    // Sequence items are values
    if (current.type === 'block_sequence' || current.type === 'flow_sequence') {
      return true;
    }

    current = current.parent;
  }

  return true; // fail-closed
}

// ── TOML: Is the node inside a pair's value (namedChild(1), not key)? ──────

function isTomlValuePosition(node: SyntaxNode, start: number, end: number): boolean {
  let current: SyntaxNode | null = node;

  while (current) {
    if (current.type === 'ERROR') { return true; } // fail-closed
    if (current.type === 'comment') { return true; } // mask secrets in comments

    if (current.type === 'pair') {
      // TOML grammar: namedChild(0) = key, namedChild(1) = value
      const keyNode = current.namedChild(0);
      if (keyNode && start >= keyNode.startIndex && end <= keyNode.endIndex) {
        return false;
      }
      return true;
    }

    // Table headers ([section]) — these are structural, not values
    if (current.type === 'table' || current.type === 'table_array_element') {
      // Check if we're inside the header brackets, not a child pair
      const bracket = current.child(0); // the '[' or '[[' token
      if (bracket && start < (current.namedChild(0)?.startIndex ?? current.endIndex)) {
        // Inside the header portion — not a value
        return false;
      }
      // We're inside a pair within the table — continue walking
    }

    if (current.type === 'array') {
      return true;
    }

    current = current.parent;
  }

  return true; // fail-closed
}

// ── XML/HTML: Is the node inside element text or attribute value? ───────────

function isXmlValuePosition(node: SyntaxNode, start: number, end: number): boolean {
  let current: SyntaxNode | null = node;

  while (current) {
    if (current.type === 'ERROR') { return true; } // fail-closed
    if (current.type === 'comment') { return true; } // mask secrets in comments

    // Tag names and attribute names are structural, not values
    if (current.type === 'tag_name') { return false; }
    if (current.type === 'attribute_name') { return false; }

    // Text content between tags is a value
    if (current.type === 'text') { return true; }

    // Attribute values are values
    if (current.type === 'attribute_value' || current.type === 'quoted_attribute_value') { return true; }

    // Inside an attribute node — if not the name, it's the value
    if (current.type === 'attribute') {
      const nameNode = current.namedChild(0);
      if (nameNode && start >= nameNode.startIndex && end <= nameNode.endIndex) {
        return false;
      }
      return true;
    }

    current = current.parent;
  }

  return true; // fail-closed
}

// ── Bash/ENV: Is the node inside a variable assignment's value? ────────────

function isEnvValuePosition(node: SyntaxNode, start: number, end: number): boolean {
  let current: SyntaxNode | null = node;

  while (current) {
    if (current.type === 'ERROR') { return true; } // fail-closed
    if (current.type === 'comment') { return true; } // mask secrets in comments

    // Variable assignment: first named child is variable_name (key)
    if (current.type === 'variable_assignment') {
      const nameNode = current.namedChild(0);
      if (nameNode && nameNode.type === 'variable_name' &&
          start >= nameNode.startIndex && end <= nameNode.endIndex) {
        return false; // It's the key name
      }
      return true; // It's the value side
    }

    // Bare variable_name outside assignment — structural
    if (current.type === 'variable_name') { return false; }

    current = current.parent;
  }

  return true; // fail-closed
}

// ────────────────────────────────────────────────────────────────────────────
// Bulk Verification — Filter Gitleaks findings through CST
// ────────────────────────────────────────────────────────────────────────────

/**
 * Parses the text once, then verifies each Gitleaks finding falls inside
 * a value node. Returns only findings whose Secret is in a value position.
 *
 * Accepts an optional pre-parsed tree (for parallel Gitleaks + parse).
 * When a pre-parsed tree is provided, the caller is responsible for deleting it.
 *
 * On CST parse failure: returns ALL findings unfiltered (fail-closed —
 * mask everything rather than leak secrets).
 */
export async function verifyFindings(
  text: string,
  lang: SupportedLang,
  findings: GitleaksFinding[],
  preParsedTree?: import('web-tree-sitter').Tree | null,
): Promise<GitleaksFinding[]> {
  if (findings.length === 0) { return []; }

  // INI: custom regex-based verification (no tree-sitter grammar available)
  if (lang === 'ini') { return verifyIniFindings(text, findings); }

  let tree: import('web-tree-sitter').Tree | null = preParsedTree ?? null;
  const ownsTree = !preParsedTree;

  if (!tree) {
    try {
      tree = await parseCST(text, lang);
    } catch (err) {
      console.warn(`[SafeChat] CST parse failed for ${lang} during verification, keeping all findings:`, err);
      return findings; // fail-closed
    }
  }

  if (!tree) {
    console.warn(`[SafeChat] CST parse returned null for ${lang}, keeping all findings`);
    return findings; // fail-closed
  }

  try {
    const root = tree.rootNode;
    return verifyFindingsCore(text, lang, findings, root);
  } catch (err) {
    console.warn(`[SafeChat] CST verification failed for ${lang}, keeping all findings:`, err);
    return findings; // fail-closed
  } finally {
    if (ownsTree && tree) { tree.delete(); }
  }
}

/**
 * Core verification loop: checks each finding against a pre-parsed CST root.
 */
function verifyFindingsCore(
  text: string,
  lang: SupportedLang,
  findings: GitleaksFinding[],
  root: SyntaxNode,
): GitleaksFinding[] {
  const verified: GitleaksFinding[] = [];

  for (const finding of findings) {
    const secret = finding.Secret;
    if (!secret || secret.length === 0) {
      verified.push(finding); // no secret to verify → keep (fail-closed)
      continue;
    }

    const approxByteOffset = lineColToByteOffset(text, finding.StartLine, finding.StartColumn);
    const approxOffset = byteOffsetToCharIndex(text, approxByteOffset);
    const secretStart = locateSecret(text, secret, approxOffset);

    if (secretStart < 0) {
      verified.push(finding); // can't locate → keep (fail-closed)
      continue;
    }

    const secretEnd = secretStart + secret.length;

    if (verifyFindingIsValueNode(root, lang, secretStart, secretEnd)) {
      verified.push(finding);
    }
    // else: finding is in a key/structural position — drop it
  }

  return verified;
}

// ── INI: Custom regex-based verification (no WASM grammar exists) ──────────

function verifyIniFindings(text: string, findings: GitleaksFinding[]): GitleaksFinding[] {
  const lines = text.split('\n');
  let offset = 0;

  interface IniLine {
    offset: number;
    isComment: boolean;
    isSection: boolean;
    valueStart: number; // char offset where value begins, -1 if none
  }

  const lineInfos: IniLine[] = [];

  for (const line of lines) {
    const trimmed = line.trimStart();
    const info: IniLine = {
      offset,
      isComment: false,
      isSection: false,
      valueStart: -1,
    };

    if (trimmed.startsWith(';') || trimmed.startsWith('#')) {
      info.isComment = true;
    } else if (/^\[.+\]/.test(trimmed)) {
      info.isSection = true;
    } else {
      const eqIdx = line.indexOf('=');
      if (eqIdx >= 0) {
        info.valueStart = offset + eqIdx + 1;
      }
    }

    lineInfos.push(info);
    offset += line.length + 1; // +1 for \n
  }

  return findings.filter(finding => {
    const secret = finding.Secret;
    if (!secret || secret.length === 0) { return true; } // fail-closed

    const approxByteOffset = lineColToByteOffset(text, finding.StartLine, finding.StartColumn);
    const approxOffset = byteOffsetToCharIndex(text, approxByteOffset);
    const secretStart = locateSecret(text, secret, approxOffset);

    if (secretStart < 0) { return true; } // fail-closed

    const lineIdx = finding.StartLine;
    if (lineIdx < 0 || lineIdx >= lineInfos.length) { return true; } // fail-closed

    const info = lineInfos[lineIdx];

    // Comments: mask secrets in comments (fail-closed)
    if (info.isComment) { return true; }

    // Section headers: structural, not values
    if (info.isSection) { return false; }

    // Key=value: secret in value portion → mask; in key → drop
    if (info.valueStart >= 0) {
      return secretStart >= info.valueStart;
    }

    return true; // fail-closed
  });
}

// ── JSONL: Per-line JSON CST verification ──────────────────────────────────

/**
 * Verifies Gitleaks findings against per-line JSON CST for JSONL/NDJSON files.
 * Scans the full text with Gitleaks once, then verifies each finding by
 * parsing only the line it falls on as standalone JSON.
 */
export async function verifyJsonlFindings(
  text: string,
  findings: GitleaksFinding[],
): Promise<GitleaksFinding[]> {
  if (findings.length === 0) { return []; }

  const lines = text.split('\n');

  // Group findings by line for efficient per-line parsing
  const byLine = new Map<number, GitleaksFinding[]>();
  for (const f of findings) {
    const arr = byLine.get(f.StartLine) ?? [];
    arr.push(f);
    byLine.set(f.StartLine, arr);
  }

  const verified: GitleaksFinding[] = [];

  for (const [lineNum, lineFindings] of byLine) {
    const lineText = lines[lineNum];
    if (!lineText?.trim()) {
      verified.push(...lineFindings); // fail-closed
      continue;
    }

    let tree: import('web-tree-sitter').Tree | null = null;
    try {
      tree = await parseCST(lineText, 'json');
    } catch {
      verified.push(...lineFindings); // fail-closed
      continue;
    }

    if (!tree) {
      verified.push(...lineFindings); // fail-closed
      continue;
    }

    try {
      const root = tree.rootNode;
      for (const finding of lineFindings) {
        const secret = finding.Secret;
        if (!secret) { verified.push(finding); continue; }

        // Locate secret within the line text using column hint
        const idx = lineText.indexOf(secret, Math.max(0, finding.StartColumn - 50));
        const effectiveIdx = idx >= 0 ? idx : lineText.indexOf(secret);

        if (effectiveIdx < 0) {
          verified.push(finding); // fail-closed
          continue;
        }

        if (verifyFindingIsValueNode(root, 'json', effectiveIdx, effectiveIdx + secret.length)) {
          verified.push(finding);
        }
      }
    } catch {
      verified.push(...lineFindings); // fail-closed
    } finally {
      tree.delete();
    }
  }

  return verified;
}

/**
 * Locate the exact character offset of a secret string near an approximate
 * byte offset. Mirrors the search logic from applyMask in gitleaksEngine.ts.
 * Returns -1 if not found.
 */
function locateSecret(text: string, secret: string, approxOffset: number): number {
  const searchStart = Math.max(0, approxOffset - 500);
  const searchEnd = Math.min(text.length, approxOffset + secret.length + 500);
  const searchWindow = text.slice(searchStart, searchEnd);

  // Search near expected position first
  const relativeApprox = Math.max(0, approxOffset - searchStart - 50);
  const idx = searchWindow.indexOf(secret, relativeApprox);
  if (idx >= 0) { return searchStart + idx; }

  // Fallback: search from window start
  const idx2 = searchWindow.indexOf(secret);
  if (idx2 >= 0) { return searchStart + idx2; }

  // Last resort: search entire text
  const globalIdx = text.indexOf(secret);
  return globalIdx; // -1 if not found
}
