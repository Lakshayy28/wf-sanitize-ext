"use strict";
/**
 * gitleaksEngine.ts — Gitleaks Secret Detection Engine
 * ═══════════════════════════════════════════════════════
 * Spawns a bundled Gitleaks binary via stdin/stdout for secret detection.
 * No disk writes — all detection happens via pipes.
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
exports.getGitleaksBinary = getGitleaksBinary;
exports.scanWithGitleaks = scanWithGitleaks;
exports.byteOffsetToCharIndex = byteOffsetToCharIndex;
exports.lineColToByteOffset = lineColToByteOffset;
exports.applyMask = applyMask;
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const fs = __importStar(require("fs"));
// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS = 10_000;
// ────────────────────────────────────────────────────────────────────────────
// Binary Resolution
// ────────────────────────────────────────────────────────────────────────────
/**
 * Resolves the platform-specific Gitleaks binary path.
 * Binaries are stored in `server/<platform>-<arch>/gitleaks[.exe]`.
 */
function getGitleaksBinary(extensionPath) {
    const platform = os.platform(); // 'darwin', 'linux', 'win32'
    const arch = os.arch(); // 'arm64', 'x64'
    let platformDir;
    switch (platform) {
        case 'darwin':
            if (arch !== 'arm64') {
                throw new Error(`[SafeChat] Only Apple Silicon (arm64) is supported on macOS. Detected: ${arch}`);
            }
            platformDir = 'darwin-arm64';
            break;
        case 'win32':
            platformDir = 'win-x64';
            break;
        default:
            throw new Error(`[SafeChat] Unsupported platform: ${platform}-${arch}. Supported: darwin-arm64, win32-x64`);
    }
    const binaryName = platform === 'win32' ? 'gitleaks.exe' : 'gitleaks';
    const binaryPath = path.join(extensionPath, 'server', platformDir, binaryName);
    if (!fs.existsSync(binaryPath)) {
        throw new Error(`[SafeChat] Gitleaks binary not found at: ${binaryPath}. ` +
            `Download the correct binary from https://github.com/gitleaks/gitleaks/releases`);
    }
    return binaryPath;
}
// ────────────────────────────────────────────────────────────────────────────
// Scanning
// ────────────────────────────────────────────────────────────────────────────
/**
 * Scans text for secrets using Gitleaks via stdin pipe.
 *
 * @param text - The text content to scan
 * @param configPath - Path to a Gitleaks TOML config file
 * @param binaryPath - Path to the Gitleaks binary (pre-resolved)
 * @param timeoutMs - Maximum time to wait for Gitleaks (default: 10s)
 * @returns Array of findings (empty if clean)
 */
function scanWithGitleaks(text, configPath, binaryPath, timeoutMs = DEFAULT_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        // Write report to a temp file (works on all platforms including macOS and Windows)
        const tempReportPath = path.join(os.tmpdir(), `gitleaks-report-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
        // Build args: detect mode, pipe from stdin, JSON report to temp file
        const args = [
            'detect',
            '--pipe',
            '--report-format', 'json',
            '--report-path', tempReportPath,
            '--config', configPath,
        ];
        // Run from os.tmpdir() to avoid scanning workspace files
        const child = (0, child_process_1.spawn)(binaryPath, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: os.tmpdir(),
        });
        let stdout = '';
        let stderr = '';
        let stdoutBytes = 0;
        const MAX_STDOUT = 50 * 1024 * 1024; // 50MB
        child.stdout.on('data', (data) => {
            stdoutBytes += data.length;
            if (stdoutBytes > MAX_STDOUT) {
                try {
                    child.kill('SIGKILL');
                }
                catch (_) { }
                reject(new Error('[SafeChat] Gitleaks stdout exceeded 50MB. Aborting.'));
                return;
            }
            stdout += data.toString();
        });
        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        // Write text to stdin and close
        child.stdin.write(text);
        child.stdin.end();
        const timer = setTimeout(() => {
            child.kill('SIGTERM');
            setTimeout(() => { try {
                child.kill('SIGKILL');
            }
            catch (_) { } }, 5000);
            cleanupTempFile(tempReportPath);
            reject(new Error(`[SafeChat] Gitleaks timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        child.on('close', (code) => {
            clearTimeout(timer);
            // Exit codes: 0 = no leaks, 1 = leaks found, 2+ = error
            if (code !== null && code >= 2) {
                cleanupTempFile(tempReportPath);
                reject(new Error(`[SafeChat] Gitleaks exited with code ${code}: ${stderr.trim()}`));
                return;
            }
            // Read findings from temp report file
            let reportJson = '';
            try {
                if (fs.existsSync(tempReportPath)) {
                    reportJson = fs.readFileSync(tempReportPath, 'utf-8');
                }
            }
            finally {
                cleanupTempFile(tempReportPath);
            }
            // Parse findings
            const trimmed = reportJson.trim();
            if (!trimmed || trimmed === 'null') {
                resolve([]);
                return;
            }
            try {
                const findings = JSON.parse(trimmed);
                if (!Array.isArray(findings)) {
                    resolve([]);
                    return;
                }
                resolve(findings);
            }
            catch (parseErr) {
                // If stdout contains non-JSON noise (e.g., log messages mixed with JSON),
                // attempt to extract the JSON array
                const jsonMatch = trimmed.match(/\[[\s\S]*\]/);
                if (jsonMatch) {
                    try {
                        const extracted = JSON.parse(jsonMatch[0]);
                        resolve(Array.isArray(extracted) ? extracted : []);
                        return;
                    }
                    catch {
                        // fall through
                    }
                }
                console.warn('[SafeChat] Failed to parse Gitleaks output:', parseErr);
                resolve([]);
            }
        });
        child.on('error', (err) => {
            clearTimeout(timer);
            cleanupTempFile(tempReportPath);
            reject(new Error(`[SafeChat] Failed to spawn Gitleaks: ${err.message}`));
        });
    });
}
function cleanupTempFile(filePath) {
    if (filePath) {
        try {
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }
        catch {
            // Ignore cleanup errors
        }
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Masking
// ────────────────────────────────────────────────────────────────────────────
/**
 * Converts a byte offset (from Gitleaks) to a character index (for JS string ops).
 * Essential for non-ASCII text (emojis, CJK, etc.) where byte ≠ char.
 */
function byteOffsetToCharIndex(text, byteOffset) {
    const buf = Buffer.from(text, 'utf-8');
    if (byteOffset >= buf.length) {
        return text.length;
    }
    return buf.subarray(0, byteOffset).toString('utf-8').length;
}
/**
 * Computes the byte offset for a line:column position in a text string.
 * Gitleaks reports 0-indexed lines and columns.
 */
function lineColToByteOffset(text, line, col) {
    const lines = text.split('\n');
    let byteOffset = 0;
    for (let i = 0; i < line && i < lines.length; i++) {
        byteOffset += Buffer.byteLength(lines[i], 'utf-8') + 1; // +1 for \n
    }
    if (line < lines.length) {
        const lineText = lines[line];
        // Column is character-based; convert to bytes
        const prefix = lineText.slice(0, col);
        byteOffset += Buffer.byteLength(prefix, 'utf-8');
    }
    return byteOffset;
}
/**
 * Applies masking to the original text based on Gitleaks findings.
 *
 * Strategy:
 * 1. For each finding, locate the `Secret` substring within the original text
 *    using line/column positions from the finding.
 * 2. Sort replacements by position (descending) to avoid offset drift.
 * 3. Replace each secret with the mask token.
 */
function applyMask(text, findings, mask) {
    if (findings.length === 0) {
        return { cleanText: text, wasModified: false, redactions: [] };
    }
    const redactions = [];
    // Deduplicate findings by secret value and position to avoid double-masking
    const seen = new Set();
    const uniqueFindings = [];
    for (const f of findings) {
        const key = `${f.StartLine}:${f.StartColumn}:${f.Secret}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueFindings.push(f);
        }
    }
    const regions = [];
    for (const finding of uniqueFindings) {
        const secret = finding.Secret;
        if (!secret || secret.length === 0) {
            continue;
        }
        // Use line/column to compute approximate byte offset, then convert to char index
        const approxByteOffset = lineColToByteOffset(text, finding.StartLine, finding.StartColumn);
        const approxOffset = byteOffsetToCharIndex(text, approxByteOffset);
        // Search for the secret near the approximate offset (±500 chars to handle encoding variance)
        const searchStart = Math.max(0, approxOffset - 500);
        const searchEnd = Math.min(text.length, approxOffset + secret.length + 500);
        const searchWindow = text.slice(searchStart, searchEnd);
        // Start searching from near the expected position, not from the window start,
        // to correctly handle the same secret appearing at multiple positions
        const relativeApprox = Math.max(0, approxOffset - searchStart - 50);
        const idx = searchWindow.indexOf(secret, relativeApprox);
        // If not found near expected position, try from window start
        const effectiveIdx = idx >= 0 ? idx : searchWindow.indexOf(secret);
        if (effectiveIdx >= 0) {
            const absoluteStart = searchStart + effectiveIdx;
            regions.push({
                start: absoluteStart,
                end: absoluteStart + secret.length,
                ruleId: finding.RuleID,
            });
            redactions.push(finding.RuleID || finding.Description);
        }
        else {
            // Fallback: search entire text for the secret
            const globalIdx = text.indexOf(secret);
            if (globalIdx >= 0) {
                regions.push({
                    start: globalIdx,
                    end: globalIdx + secret.length,
                    ruleId: finding.RuleID,
                });
                redactions.push(finding.RuleID || finding.Description);
            }
            else {
                console.warn(`[SafeChat] Could not locate secret for rule ${finding.RuleID} in text`);
            }
        }
    }
    if (regions.length === 0) {
        return { cleanText: text, wasModified: false, redactions: [] };
    }
    // Sort descending by start position to replace from end → start (avoids offset drift)
    regions.sort((a, b) => b.start - a.start);
    // Merge overlapping regions
    const merged = [regions[0]];
    for (let i = 1; i < regions.length; i++) {
        const current = regions[i];
        const last = merged[merged.length - 1];
        if (current.end > last.start) {
            // Overlapping — extend the region
            last.start = Math.min(last.start, current.start);
            last.ruleId = `${current.ruleId},${last.ruleId}`;
        }
        else {
            merged.push(current);
        }
    }
    // Apply replacements from end to start
    let result = text;
    for (const region of merged) {
        result = result.slice(0, region.start) + mask + result.slice(region.end);
    }
    return { cleanText: result, wasModified: true, redactions };
}
//# sourceMappingURL=gitleaksEngine.js.map