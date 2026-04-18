"use strict";
/**
 * treeSitterEngine.ts — Tree-Sitter CST Verification Engine
 * ═════════════════════════════════════════════════════════
 * Loads WASM grammars for JSON, YAML, TOML.
 * Used as a VERIFIER: after Gitleaks scans raw text and finds secrets,
 * Tree-Sitter confirms each finding falls inside a value node (not a key
 * or structural element). This preserves 100% of Gitleaks' context while
 * adding 100% of Tree-Sitter's structural precision.
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
exports.initTreeSitter = initTreeSitter;
exports.parseCST = parseCST;
exports.verifyFindingIsValueNode = verifyFindingIsValueNode;
exports.verifyFindings = verifyFindings;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
// ────────────────────────────────────────────────────────────────────────────
// State — Parser & Grammar Cache
// ────────────────────────────────────────────────────────────────────────────
let Parser = null;
let parserInstance = null;
const grammarCache = new Map();
let extensionBasePath = '';
// ────────────────────────────────────────────────────────────────────────────
// Initialization
// ────────────────────────────────────────────────────────────────────────────
/**
 * Initialize the Tree-Sitter WASM runtime. Must be called once at activation.
 * @param extPath - The VS Code extension's install path (context.extensionPath)
 */
async function initTreeSitter(extPath) {
    extensionBasePath = extPath;
    if (Parser) {
        return;
    } // Already initialized
    const P = require('web-tree-sitter');
    const grammarsDir = path.join(extPath, 'grammars');
    await P.init({
        locateFile: (file) => path.join(grammarsDir, file),
    });
    Parser = P;
    parserInstance = new P();
}
/**
 * Load a language grammar WASM. Cached after first load.
 */
async function loadGrammar(lang) {
    const cached = grammarCache.get(lang);
    if (cached) {
        return cached;
    }
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
 * Returns null if parsing fails (caller should fall back to raw scan).
 */
async function parseCST(text, lang) {
    if (!parserInstance) {
        throw new Error('[SafeChat] Tree-Sitter not initialized. Call initTreeSitter() first.');
    }
    const grammar = await loadGrammar(lang);
    parserInstance.setLanguage(grammar);
    return parserInstance.parse(text);
}
// ────────────────────────────────────────────────────────────────────────────
// Two-Pass Verification — Gitleaks Finding Verifier
// ────────────────────────────────────────────────────────────────────────────
const gitleaksEngine_1 = require("./gitleaksEngine");
/**
 * Checks whether a byte range [startIndex, endIndex) falls inside a VALUE
 * node in the CST (not a key, property name, section header, or structure).
 *
 * Uses `descendantForIndex` to find the deepest node spanning the range,
 * then walks UP via `.parent` to determine structural context per grammar.
 *
 * Fail-closed: returns `true` (mask it) when context is ambiguous or ERROR.
 */
function verifyFindingIsValueNode(root, lang, startIndex, endIndex) {
    // descendantForIndex uses inclusive end, so subtract 1
    const node = root.descendantForIndex(startIndex, Math.max(startIndex, endIndex - 1));
    if (!node) {
        return true;
    } // fail-closed
    switch (lang) {
        case 'json':
            return isJsonValuePosition(node, startIndex, endIndex);
        case 'yaml':
            return isYamlValuePosition(node, startIndex, endIndex);
        case 'toml':
            return isTomlValuePosition(node, startIndex, endIndex);
        default:
            return true; // unknown lang → fail-closed
    }
}
// ── JSON: Is the node inside a pair's value (not key)? ─────────────────────
function isJsonValuePosition(node, start, end) {
    let current = node;
    while (current) {
        if (current.type === 'ERROR') {
            return true;
        } // fail-closed
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
function isYamlValuePosition(node, start, end) {
    let current = node;
    while (current) {
        if (current.type === 'ERROR') {
            return true;
        } // fail-closed
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
function isTomlValuePosition(node, start, end) {
    let current = node;
    while (current) {
        if (current.type === 'ERROR') {
            return true;
        } // fail-closed
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
// ────────────────────────────────────────────────────────────────────────────
// Bulk Verification — Filter Gitleaks findings through CST
// ────────────────────────────────────────────────────────────────────────────
/**
 * Parses the text once, then verifies each Gitleaks finding falls inside
 * a value node. Returns only findings whose Secret is in a value position.
 *
 * On CST parse failure: returns ALL findings unfiltered (fail-closed —
 * mask everything rather than leak secrets).
 */
async function verifyFindings(text, lang, findings) {
    if (findings.length === 0) {
        return [];
    }
    let tree = null;
    try {
        tree = await parseCST(text, lang);
    }
    catch (err) {
        console.warn(`[SafeChat] CST parse failed for ${lang} during verification, keeping all findings:`, err);
        return findings; // fail-closed
    }
    if (!tree) {
        console.warn(`[SafeChat] CST parse returned null for ${lang}, keeping all findings`);
        return findings; // fail-closed
    }
    try {
        const root = tree.rootNode;
        const verified = [];
        for (const finding of findings) {
            const secret = finding.Secret;
            if (!secret || secret.length === 0) {
                verified.push(finding); // no secret to verify → keep (fail-closed)
                continue;
            }
            // Resolve the secret's byte position in the original text
            // using the same logic as applyMask in gitleaksEngine.ts
            const approxOffset = (0, gitleaksEngine_1.lineColToByteOffset)(text, finding.StartLine, finding.StartColumn);
            const secretStart = locateSecret(text, secret, approxOffset);
            if (secretStart < 0) {
                // Can't locate the secret in text — keep it anyway (fail-closed)
                verified.push(finding);
                continue;
            }
            const secretEnd = secretStart + secret.length;
            if (verifyFindingIsValueNode(root, lang, secretStart, secretEnd)) {
                verified.push(finding);
            }
            // else: finding is in a key/structural position — drop it
        }
        tree.delete();
        return verified;
    }
    catch (err) {
        console.warn(`[SafeChat] CST verification failed for ${lang}, keeping all findings:`, err);
        if (tree) {
            tree.delete();
        }
        return findings; // fail-closed
    }
}
/**
 * Locate the exact character offset of a secret string near an approximate
 * byte offset. Mirrors the search logic from applyMask in gitleaksEngine.ts.
 * Returns -1 if not found.
 */
function locateSecret(text, secret, approxOffset) {
    const searchStart = Math.max(0, approxOffset - 500);
    const searchEnd = Math.min(text.length, approxOffset + secret.length + 500);
    const searchWindow = text.slice(searchStart, searchEnd);
    // Search near expected position first
    const relativeApprox = Math.max(0, approxOffset - searchStart - 50);
    const idx = searchWindow.indexOf(secret, relativeApprox);
    if (idx >= 0) {
        return searchStart + idx;
    }
    // Fallback: search from window start
    const idx2 = searchWindow.indexOf(secret);
    if (idx2 >= 0) {
        return searchStart + idx2;
    }
    // Last resort: search entire text
    const globalIdx = text.indexOf(secret);
    return globalIdx; // -1 if not found
}
//# sourceMappingURL=treeSitterEngine.js.map