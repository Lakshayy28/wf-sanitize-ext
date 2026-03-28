"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.initializeTreeSitter = initializeTreeSitter;
exports.getTreeSitterParser = getTreeSitterParser;
exports.isTreeSitterReady = isTreeSitterReady;
const vscode = __importStar(require("vscode"));
const web_tree_sitter_1 = require("web-tree-sitter");
const GRAMMAR_FILES = {
    bash: 'tree-sitter-bash.wasm',
    json: 'tree-sitter-json.wasm',
    properties: 'tree-sitter-properties.wasm',
    yaml: 'tree-sitter-yaml.wasm',
};
// ── Singleton state ─────────────────────────────────────────────────────────
let parser = null;
const languages = new Map();
let initPromise = null;
// ── Public API ──────────────────────────────────────────────────────────────
/**
 * Initialize the Tree-sitter runtime and load all available grammars.
 * Safe to call multiple times — only the first call performs work.
 * Individual grammar load failures are logged but don't block others.
 */
function initializeTreeSitter(extensionUri) {
    if (initPromise) {
        return initPromise;
    }
    initPromise = (async () => {
        const runtimeWasmPath = vscode.Uri.joinPath(extensionUri, 'wasm', 'tree-sitter.wasm').fsPath;
        // Initialize the Tree-sitter runtime (Emscripten module)
        await web_tree_sitter_1.Parser.init({
            locateFile: () => runtimeWasmPath,
        });
        // Create the shared parser instance
        parser = new web_tree_sitter_1.Parser();
        // Load each grammar in parallel — failures are isolated
        const entries = Object.entries(GRAMMAR_FILES);
        await Promise.all(entries.map(async ([lang, file]) => {
            try {
                const wasmPath = vscode.Uri.joinPath(extensionUri, 'wasm', file).fsPath;
                const language = await web_tree_sitter_1.Language.load(wasmPath);
                languages.set(lang, language);
            }
            catch (err) {
                console.warn(`[SafeChat] Failed to load Tree-sitter grammar "${lang}":`, err);
            }
        }));
        // Default to bash if available (backward-compat)
        const bashLang = languages.get('bash');
        if (bashLang) {
            parser.setLanguage(bashLang);
        }
    })();
    return initPromise;
}
/**
 * Returns a Tree-sitter parser configured for the given language.
 * Throws if runtime isn't initialized or the requested grammar wasn't loaded.
 */
function getTreeSitterParser(lang) {
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
function isTreeSitterReady(lang) {
    if (!parser) {
        return false;
    }
    if (lang) {
        return languages.has(lang);
    }
    return true;
}
//# sourceMappingURL=treeSitterManager.js.map