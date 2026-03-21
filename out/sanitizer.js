"use strict";
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
exports.regexSanitize = regexSanitize;
exports.sanitizeAndCache = sanitizeAndCache;
exports.viewDiffCommand = viewDiffCommand;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
// ────────────────────────────────────────────────────────────────────────────
// Presidio NLP bridge (Tier 1 — advanced PII masking)
// ────────────────────────────────────────────────────────────────────────────
/**
 * Spawns the Presidio Python engine as a child process.
 * Sends `text` via stdin, collects anonymized output from stdout.
 *
 * Rejects if:
 *  - Python is not installed
 *  - Presidio dependencies are missing (exit code 2)
 *  - The process errors out for any other reason
 *
 * Prerequisites (remind developers):
 *   pip install presidio-analyzer presidio-anonymizer
 *   python -m spacy download en_core_web_lg
 */
function runPresidio(text, extensionPath) {
    return new Promise((resolve, reject) => {
        const scriptPath = path.join(extensionPath, 'src', 'presidio_engine.py');
        // Resolve Python interpreter — prefer the bundled .venv, then system python3/python.
        const venvPython = path.join(extensionPath, '.venv', process.platform === 'win32' ? path.join('Scripts', 'python.exe') : path.join('bin', 'python'));
        const systemPython = process.platform === 'win32' ? 'python' : 'python3';
        const pythonBin = require('fs').existsSync(venvPython) ? venvPython : systemPython;
        const child = (0, child_process_1.spawn)(pythonBin, [scriptPath], {
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });
        child.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });
        child.on('error', (err) => {
            // Typically "ENOENT" — python not found on PATH
            reject(new Error(`Failed to launch Python: ${err.message}`));
        });
        child.on('close', (code) => {
            if (code === 0) {
                resolve(stdout);
            }
            else if (code === 2) {
                // Special exit code from presidio_engine.py → Presidio not installed
                reject(new Error('Presidio is not installed on this machine.'));
            }
            else {
                reject(new Error(`Presidio process exited with code ${code}: ${stderr.trim()}`));
            }
        });
        // Write the raw text to the child's stdin and close the stream.
        child.stdin.write(text);
        child.stdin.end();
    });
}
// ────────────────────────────────────────────────────────────────────────────
// Regex-based secret masking (Tier 2 — fallback)
// ────────────────────────────────────────────────────────────────────────────
/**
 * A robust regex that matches common secret patterns:
 *  - Keys like password, passwd, secret, api_key, apikey, api-key, token,
 *    access_token, auth_token, private_key, client_secret, credentials, etc.
 *  - Followed by an assignment operator ( = , : , := , => ) with optional quotes.
 *  - Captures the value portion (the actual secret).
 *
 * Also matches standalone patterns:
 *  - Bearer tokens:       Bearer <token>
 *  - AWS keys:            AKIA[0-9A-Z]{16}
 *  - Generic hex/base64:  long high-entropy strings following a key name
 */
const SECRET_KEY_REGEX = new RegExp(
// ── Named-key = value patterns ───────────────────────────────────────
'(' +
    // Key names (case-insensitive)
    '(?:password|passwd|pwd|secret|api_?key|api[-_]?secret|token|access_?token|' +
    'auth_?token|refresh_?token|private_?key|client_?secret|credentials|' +
    'database_?url|db_?password|connection_?string|encryption_?key|' +
    'jwt_?secret|session_?secret|signing_?key|bearer)' +
    // Assignment operators with optional surrounding whitespace
    '\\s*[:=]\\s*' +
    // Optional opening quote
    '["\']?' +
    ')' +
    // The actual secret value (captured group)
    '([^\\s"\'`;,}{\\]\\)]+)' +
    '|' +
    // ── Standalone patterns ──────────────────────────────────────────────
    // Bearer tokens in Authorization headers
    '(Bearer\\s+)([A-Za-z0-9\\-._~+\\/]+=*)' +
    '|' +
    // AWS Access Key IDs
    '(AKIA[0-9A-Z]{16})', 'gi');
const MASK = '[MASKED_BY_SAFECHAT]';
/**
 * Sanitizes raw text by replacing detected secrets with a mask placeholder.
 * Returns the cleaned text and a flag indicating whether any replacements were made.
 */
function regexSanitize(rawText) {
    let wasModified = false;
    const cleanText = rawText.replace(SECRET_KEY_REGEX, (...args) => {
        wasModified = true;
        // Named-key = value  (groups 1, 2)
        if (args[1] && args[2]) {
            return args[1] + MASK;
        }
        // Bearer token        (groups 3, 4)
        if (args[3] && args[4]) {
            return args[3] + MASK;
        }
        // AWS key             (group 5)
        if (args[5]) {
            return MASK;
        }
        return MASK;
    });
    return { cleanText, wasModified };
}
// ────────────────────────────────────────────────────────────────────────────
// Cache directory helpers
// ────────────────────────────────────────────────────────────────────────────
/**
 * In-memory pointer to the most recently written cache entry.
 * Used by viewDiffCommand so the button always opens the latest diff.
 */
let latestCacheEntryUri;
/** Returns the root `.vscode/.temp_cache` base directory URI. */
function getCacheBaseUri() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        return undefined;
    }
    return vscode.Uri.joinPath(folders[0].uri, '.vscode', '.temp_cache');
}
/**
 * Generates a filesystem-safe timestamp string for use as a subfolder name.
 * e.g. "2026-03-21_10-30-00-042"
 */
function timestampSlug() {
    const now = new Date();
    const pad = (n, len = 2) => String(n).padStart(len, '0');
    return (`${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
        `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}` +
        `-${pad(now.getMilliseconds(), 3)}`);
}
/**
 * Ensures the base cache root exists and contains a wildcard .gitignore.
 * Only writes the .gitignore once (cheap stat-check first).
 */
async function ensureCacheRoot(baseUri) {
    await vscode.workspace.fs.createDirectory(baseUri);
    const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
    try {
        await vscode.workspace.fs.stat(gitignoreUri);
    }
    catch {
        // Doesn't exist yet — create it.
        await vscode.workspace.fs.writeFile(gitignoreUri, Buffer.from('*\n', 'utf-8'));
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize `rawText`, cache original + masked versions for diffing, and
 * return the clean text together with a modification flag.
 *
 * Strategy:
 *  1. Try Presidio (Tier 1) for NLP-based PII masking.
 *  2. If Presidio is unavailable, fall back to the regex engine (Tier 2).
 *  3. The regex pass always runs *after* Presidio to catch secrets that
 *     NLP alone might miss (e.g., `api_key=...` patterns).
 */
async function sanitizeAndCache(rawText, extensionPath) {
    let presidioText = rawText;
    let presidioModified = false;
    // ── Tier 1: Presidio NLP masking ───────────────────────────────────
    if (extensionPath) {
        try {
            presidioText = await runPresidio(rawText, extensionPath);
            presidioModified = presidioText !== rawText;
        }
        catch {
            // Presidio unavailable — continue with regex-only.
            // This is expected on machines without Python / Presidio.
        }
    }
    // ── Tier 2: Regex secret masking (always runs as a second pass) ────
    const { cleanText, wasModified: regexModified } = regexSanitize(presidioText);
    const wasModified = presidioModified || regexModified;
    if (wasModified) {
        const baseUri = getCacheBaseUri();
        if (baseUri) {
            await ensureCacheRoot(baseUri);
            // Each prompt gets its own timestamped subfolder — previous diffs are
            // never overwritten and remain on disk for manual inspection.
            const entryDir = vscode.Uri.joinPath(baseUri, timestampSlug());
            await vscode.workspace.fs.createDirectory(entryDir);
            const originalUri = vscode.Uri.joinPath(entryDir, 'original_context.txt');
            const maskedUri = vscode.Uri.joinPath(entryDir, 'masked_context.txt');
            await Promise.all([
                vscode.workspace.fs.writeFile(originalUri, Buffer.from(rawText, 'utf-8')),
                vscode.workspace.fs.writeFile(maskedUri, Buffer.from(cleanText, 'utf-8')),
            ]);
            // Update the in-memory pointer so the command-palette fallback works
            // after an extension reload (no button argument available then).
            latestCacheEntryUri = entryDir;
            return { cleanText, wasModified, cacheEntryUri: entryDir };
        }
    }
    return { cleanText, wasModified };
}
/**
 * Opens the VS Code diff editor comparing the original and masked context files.
 * Bound to the `safecopilot.viewDiff` command.
 */
async function viewDiffCommand(entryUriString) {
    // If the button passed a specific entry URI, use it directly.
    // This ensures each chat button always opens its own prompt's diff,
    // regardless of how many prompts have run since.
    if (entryUriString) {
        const entryUri = vscode.Uri.parse(entryUriString);
        const originalUri = vscode.Uri.joinPath(entryUri, 'original_context.txt');
        const maskedUri = vscode.Uri.joinPath(entryUri, 'masked_context.txt');
        await vscode.commands.executeCommand('vscode.diff', originalUri, maskedUri, `Original ↔ Sanitized  [${entryUri.path.split('/').pop()}]`);
        return;
    }
    // Fallback path: command palette invocation (no argument) — recover
    // the most recent entry from memory or disk.
    if (!latestCacheEntryUri) {
        // No in-memory pointer — extension may have reloaded. Try to recover the
        // most recent timestamped subfolder from disk.
        const baseUri = getCacheBaseUri();
        if (baseUri) {
            try {
                const entries = await vscode.workspace.fs.readDirectory(baseUri);
                const dirs = entries
                    .filter(([, type]) => type === vscode.FileType.Directory)
                    .map(([name]) => name)
                    .sort() // ISO timestamps sort lexicographically = chronologically
                    .reverse();
                if (dirs.length > 0) {
                    latestCacheEntryUri = vscode.Uri.joinPath(baseUri, dirs[0]);
                }
            }
            catch {
                // base dir not created yet — fall through to the warning below.
            }
        }
    }
    if (!latestCacheEntryUri) {
        vscode.window.showWarningMessage('SafeChat: No cached diff available yet. Attach a file to @safechat first.');
        return;
    }
    const originalUri = vscode.Uri.joinPath(latestCacheEntryUri, 'original_context.txt');
    const maskedUri = vscode.Uri.joinPath(latestCacheEntryUri, 'masked_context.txt');
    await vscode.commands.executeCommand('vscode.diff', originalUri, maskedUri, `Original ↔ Sanitized  [${latestCacheEntryUri.path.split('/').pop()}]`);
}
//# sourceMappingURL=sanitizer.js.map