/**
 * treeSitterManager.ts — Multi-Language Tree-sitter WASM Manager
 * ══════════════════════════════════════════════════════════════════
 * Manages async initialization of web-tree-sitter inside VS Code's
 * extension host. Loads the runtime WASM once, caches multiple language
 * grammars (bash, json, properties), and exposes per-language parsers
 * to the AST Guardian.
 *
 * Usage:
 *   await initializeTreeSitter(context.extensionUri);     // call once in activate()
 *   const parser = getTreeSitterParser('json');            // returns parser with JSON grammar
 *   if (isTreeSitterReady('properties')) { ... }           // check availability
 */

import * as vscode from 'vscode';
import { Parser, Language } from 'web-tree-sitter';

// ── Supported grammars ──────────────────────────────────────────────────────

export type TreeSitterLang = 'bash' | 'json' | 'properties' | 'yaml';

const GRAMMAR_FILES: Record<TreeSitterLang, string> = {
  bash: 'tree-sitter-bash.wasm',
  json: 'tree-sitter-json.wasm',
  properties: 'tree-sitter-properties.wasm',
  yaml: 'tree-sitter-yaml.wasm',
};

// ── Singleton state ─────────────────────────────────────────────────────────

let parser: Parser | null = null;
const languages = new Map<TreeSitterLang, Language>();
let initPromise: Promise<void> | null = null;

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Initialize the Tree-sitter runtime and load all available grammars.
 * Safe to call multiple times — only the first call performs work.
 * Individual grammar load failures are logged but don't block others.
 */
export function initializeTreeSitter(extensionUri: vscode.Uri): Promise<void> {
  if (initPromise) { return initPromise; }

  initPromise = (async () => {
    const runtimeWasmPath = vscode.Uri.joinPath(extensionUri, 'wasm', 'tree-sitter.wasm').fsPath;

    // Initialize the Tree-sitter runtime (Emscripten module)
    await Parser.init({
      locateFile: () => runtimeWasmPath,
    });

    // Create the shared parser instance
    parser = new Parser();

    // Load each grammar in parallel — failures are isolated
    const entries = Object.entries(GRAMMAR_FILES) as [TreeSitterLang, string][];
    await Promise.all(entries.map(async ([lang, file]) => {
      try {
        const wasmPath = vscode.Uri.joinPath(extensionUri, 'wasm', file).fsPath;
        const language = await Language.load(wasmPath);
        languages.set(lang, language);
      } catch (err) {
        console.warn(`[SafeChat] Failed to load Tree-sitter grammar "${lang}":`, err);
      }
    }));

    // Default to bash if available (backward-compat)
    const bashLang = languages.get('bash');
    if (bashLang) { parser.setLanguage(bashLang); }
  })();

  return initPromise;
}

/**
 * Returns a Tree-sitter parser configured for the given language.
 * Throws if runtime isn't initialized or the requested grammar wasn't loaded.
 */
export function getTreeSitterParser(lang?: TreeSitterLang): Parser {
  if (!parser) {
    throw new Error('[SafeChat] Tree-sitter parser not initialized. Call initializeTreeSitter() first.');
  }
  if (lang) {
    const language = languages.get(lang);
    if (!language) {
      throw new Error(`[SafeChat] Tree-sitter grammar "${lang}" not loaded.`);
    }
    parser.setLanguage(language);
  }
  return parser;
}

/**
 * Returns true if the Tree-sitter runtime is ready and (optionally)
 * a specific grammar is loaded.
 */
export function isTreeSitterReady(lang?: TreeSitterLang): boolean {
  if (!parser) { return false; }
  if (lang) { return languages.has(lang); }
  return true;
}
