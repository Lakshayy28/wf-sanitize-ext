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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const sanitizer_1 = require("./sanitizer");
let extensionPath;
const fileStateCache = new Map();
let conversationFileKeys = new Set();
let latestCacheEntryUri;
let lastRulesHash;
/**
 * SessionStateManager: Maps original file URI string → masked .temp_cache URI string.
 * Populated after sanitization + cache-write. Used to redirect autonomous file reads
 * to the already-sanitized versions on disk, preventing data leakage.
 */
const sessionStateMap = new Map();
// ── SafeReadFileTool — Custom LM Tool for sanitized file reads ──────────────
/**
 * A Language Model Tool that reads files and sanitizes secrets/PII before
 * returning content to the model. Registered as `safechat_read_file`.
 * Every file is sanitized regardless of extension (no allowlist filter).
 */
class SafeReadFileTool {
    /** Set by the chat handler so the tool can push UI feedback (buttons, markdown). */
    _stream;
    async invoke(options, _token) {
        const filePath = options.input.filePath;
        console.log('[SafeChat] safechat_read_file invoked for:', filePath);
        // 1. Check SessionStateManager — if already sanitized, serve cached version
        const maskedUri = resolveSessionState(filePath);
        if (maskedUri) {
            try {
                const bytes = await vscode.workspace.fs.readFile(vscode.Uri.parse(maskedUri));
                const text = Buffer.from(bytes).toString('utf-8');
                console.log('[SafeChat] safechat_read_file: served masked version from cache');
                return new vscode.LanguageModelToolResult([new vscode.LanguageModelTextPart(text)]);
            }
            catch {
                console.log('[SafeChat] safechat_read_file: cached masked file not readable, falling through');
            }
        }
        // 2. Check in-memory fileStateCache
        const cached = findCachedState(filePath);
        if (cached) {
            console.log('[SafeChat] safechat_read_file: served from fileStateCache (masked:', cached.wasMasked, ')');
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(cached.sanitizedContent),
            ]);
        }
        // 3. Read the file fresh and always sanitize
        let fileUri;
        try {
            if (filePath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(filePath)) {
                fileUri = vscode.Uri.file(filePath);
            }
            else {
                const folders = vscode.workspace.workspaceFolders;
                if (folders?.length) {
                    fileUri = vscode.Uri.joinPath(folders[0].uri, filePath);
                }
                else {
                    fileUri = vscode.Uri.file(filePath);
                }
            }
        }
        catch {
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(`Error: Invalid file path: ${filePath}`),
            ]);
        }
        try {
            const bytes = await vscode.workspace.fs.readFile(fileUri);
            const raw = Buffer.from(bytes).toString('utf-8');
            const { cleanText, wasModified } = (0, sanitizer_1.regexSanitize)(raw);
            console.log('[SafeChat] safechat_read_file: read fresh, sanitized:', wasModified);
            // Write diff cache + render UI button if masking occurred
            if (wasModified) {
                const relPath = vscode.workspace.asRelativePath(fileUri, false);
                await appendToDiffCache([{ relPath, original: raw, masked: cleanText }]);
                populateSessionStateMap([{ relPath, uri: fileUri.toString() }]);
                if (this._stream) {
                    this._stream.markdown('\n\n🛡️ **Tool execution masked sensitive data.**\n\n');
                    this._stream.button({ command: 'safecopilot.viewDiff', title: '$(diff) View Masked Diff' });
                }
            }
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(cleanText),
            ]);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(`Error reading file "${filePath}": ${msg}`),
            ]);
        }
    }
}
/** Shared instance for direct invocation in the redirect guard */
const safeReadFileToolInstance = new SafeReadFileTool();
/**
 * A Language Model Tool that recursively reads a directory, sanitizes every
 * file's contents, and returns an aggregate result. Registered as
 * `safechat_read_directory`. Enforces depth and file-count safety limits and
 * skips heavy/unsafe directories (node_modules, .git, etc.).
 */
class SafeReadDirectoryTool {
    /** Hard upper bounds to prevent runaway reads */
    static ABSOLUTE_MAX_DEPTH = 10;
    static ABSOLUTE_MAX_FILES = 200;
    /** Set by the chat handler so the tool can push UI feedback (buttons, markdown). */
    _stream;
    async invoke(options, _token) {
        const { directoryPath } = options.input;
        const maxDepth = Math.min(options.input.maxDepth ?? 5, SafeReadDirectoryTool.ABSOLUTE_MAX_DEPTH);
        const maxFiles = Math.min(options.input.maxFiles ?? 50, SafeReadDirectoryTool.ABSOLUTE_MAX_FILES);
        console.log('[SafeChat] safechat_read_directory invoked for:', directoryPath, 'maxDepth:', maxDepth, 'maxFiles:', maxFiles);
        // Resolve the directory URI
        let dirUri;
        try {
            if (directoryPath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(directoryPath)) {
                dirUri = vscode.Uri.file(directoryPath);
            }
            else {
                const folders = vscode.workspace.workspaceFolders;
                if (folders?.length) {
                    dirUri = vscode.Uri.joinPath(folders[0].uri, directoryPath);
                }
                else {
                    dirUri = vscode.Uri.file(directoryPath);
                }
            }
        }
        catch {
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(`Error: Invalid directory path: ${directoryPath}`),
            ]);
        }
        // Verify it's actually a directory
        try {
            const stat = await vscode.workspace.fs.stat(dirUri);
            if (stat.type !== vscode.FileType.Directory) {
                return new vscode.LanguageModelToolResult([
                    new vscode.LanguageModelTextPart(`Error: "${directoryPath}" is not a directory.`),
                ]);
            }
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(`Error: Cannot access directory "${directoryPath}": ${msg}`),
            ]);
        }
        // Collect files with depth + count limits
        const collectedFiles = [];
        await this.collectFilesWithLimits(dirUri, 0, maxDepth, maxFiles, collectedFiles);
        if (collectedFiles.length === 0) {
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(`Directory "${directoryPath}" is empty or contains only skipped directories.`),
            ]);
        }
        // Read and sanitize each file
        const parts = [];
        const toolMaskedFiles = [];
        let truncated = false;
        for (const fileUri of collectedFiles) {
            const relPath = vscode.workspace.asRelativePath(fileUri, false);
            // Check SessionStateManager first
            const maskedUri = resolveSessionState(fileUri.toString())
                || resolveSessionState(fileUri.fsPath)
                || resolveSessionState(relPath);
            if (maskedUri) {
                try {
                    const bytes = await vscode.workspace.fs.readFile(vscode.Uri.parse(maskedUri));
                    parts.push(`// File: ${relPath}\n${Buffer.from(bytes).toString('utf-8')}`);
                    continue;
                }
                catch { /* fall through to fresh read */ }
            }
            // Check in-memory cache
            const cached = findCachedState(fileUri.fsPath) || findCachedState(relPath);
            if (cached) {
                parts.push(`// File: ${relPath}\n${cached.sanitizedContent}`);
                continue;
            }
            // Fresh read + sanitize
            try {
                const bytes = await vscode.workspace.fs.readFile(fileUri);
                const raw = Buffer.from(bytes).toString('utf-8');
                const { cleanText, wasModified } = (0, sanitizer_1.regexSanitize)(raw);
                parts.push(`// File: ${relPath}\n${cleanText}`);
                if (wasModified) {
                    toolMaskedFiles.push({ relPath, original: raw, masked: cleanText, uri: fileUri.toString() });
                }
            }
            catch {
                parts.push(`// File: ${relPath}\n[Error: could not read file]`);
            }
        }
        if (collectedFiles.length >= maxFiles) {
            truncated = true;
        }
        // Write diff cache for any files that were masked during this directory scan
        if (toolMaskedFiles.length > 0) {
            await appendToDiffCache(toolMaskedFiles);
            populateSessionStateMap(toolMaskedFiles.map(f => ({ relPath: f.relPath, uri: f.uri })));
            if (this._stream) {
                this._stream.markdown(`\n\n🛡️ **Tool execution masked sensitive data in ${toolMaskedFiles.length} file(s).**\n\n`);
                this._stream.button({ command: 'safecopilot.viewDiff', title: '$(diff) View Masked Diff' });
            }
        }
        const header = `Directory: ${directoryPath} (${collectedFiles.length} file(s)${truncated ? `, truncated at maxFiles=${maxFiles}` : ''})\n${'─'.repeat(60)}`;
        console.log('[SafeChat] safechat_read_directory: returned', collectedFiles.length, 'files, truncated:', truncated);
        return new vscode.LanguageModelToolResult([
            new vscode.LanguageModelTextPart(header + '\n\n' + parts.join('\n\n')),
        ]);
    }
    /**
     * Recursively collects files from a directory, respecting depth limits,
     * file-count caps, and SKIP_DIRS.
     */
    async collectFilesWithLimits(dirUri, currentDepth, maxDepth, maxFiles, out) {
        if (currentDepth >= maxDepth || out.length >= maxFiles) {
            return;
        }
        let entries;
        try {
            entries = await vscode.workspace.fs.readDirectory(dirUri);
        }
        catch {
            return;
        }
        // Sort: files first (for deterministic output), then directories
        entries.sort((a, b) => {
            if (a[1] === b[1]) {
                return a[0].localeCompare(b[0]);
            }
            return a[1] === vscode.FileType.File ? -1 : 1;
        });
        for (const [name, type] of entries) {
            if (out.length >= maxFiles) {
                break;
            }
            if (type === vscode.FileType.File) {
                out.push(vscode.Uri.joinPath(dirUri, name));
            }
            else if (type === vscode.FileType.Directory) {
                if (SKIP_DIRS.has(name)) {
                    continue;
                }
                await this.collectFilesWithLimits(vscode.Uri.joinPath(dirUri, name), currentDepth + 1, maxDepth, maxFiles, out);
            }
        }
    }
}
/** Shared instance for direct invocation in the redirect guard */
const safeReadDirToolInstance = new SafeReadDirectoryTool();
// ── Activation ──────────────────────────────────────────────────────────────
function activate(context) {
    extensionPath = context.extensionPath;
    const participant = vscode.chat.createChatParticipant('safecopilot.safeChat', chatRequestHandler);
    participant.iconPath = new vscode.ThemeIcon('shield');
    const diffCmd = vscode.commands.registerCommand('safecopilot.viewDiff', handleViewDiff);
    // Register custom safe tools
    const fileToolDisposable = vscode.lm.registerTool('safechat_read_file', safeReadFileToolInstance);
    const dirToolDisposable = vscode.lm.registerTool('safechat_read_directory', safeReadDirToolInstance);
    context.subscriptions.push(participant, diffCmd, fileToolDisposable, dirToolDisposable);
}
// ── Native Tool Detection ───────────────────────────────────────────────────
/**
 * Patterns matching known native file-read tool names that would bypass our
 * sanitization. These are stripped from the tool menu so the model can only
 * use safechat_read_file.
 */
const NATIVE_FILE_READ_PATTERNS = [
    /^vscode_readFile$/i,
    /^readFile$/i,
    /^read_file$/i,
    /^file_read$/i,
    /^vscode[-_.]?read/i,
    /^copilot[-_.]?read/i,
    /^mcp_.*read.*file/i,
    /^mcp_.*file.*content/i,
    /^mcp_.*get.*file/i,
];
/** Keywords in tool descriptions that indicate file-reading capability */
const FILE_READ_DESC_KEYWORDS = [
    'read the contents of a file',
    'read a file',
    'contents of a file',
    'file contents',
    'read file',
];
/** Returns true if a tool is a native file-read tool that should be blocked */
function isNativeFileReadTool(name, description) {
    if (name === 'safechat_read_file') {
        return false;
    } // Never block our own tool
    if (NATIVE_FILE_READ_PATTERNS.some(p => p.test(name))) {
        return true;
    }
    const descLower = description.toLowerCase();
    return FILE_READ_DESC_KEYWORDS.some(kw => descLower.includes(kw));
}
// ── Native Directory Tool Detection ─────────────────────────────────────────
const NATIVE_DIR_PATTERNS = [
    /list_?dir(?:ectory)?/i,
    /read_?dir(?:ectory)?/i,
    /read_?folder/i,
    /list_?folder/i,
    /dir(?:ectory)?_?contents?/i,
    /vscode_.*dir(?:ectory)?/i,
    /mcp_.*(?:dir|folder)/i,
];
const DIR_READ_DESC_KEYWORDS = [
    'list directory', 'read folder', 'directory contents',
    'files in a folder', 'enumerate files', 'list files in',
];
/** Returns true if a tool is a native directory/folder-listing tool */
function isNativeDirectoryTool(name, description) {
    if (name === 'safechat_read_directory') {
        return false;
    }
    if (NATIVE_DIR_PATTERNS.some(p => p.test(name))) {
        return true;
    }
    const descLower = description.toLowerCase();
    return DIR_READ_DESC_KEYWORDS.some(kw => descLower.includes(kw));
}
// ── Native Search Tool Detection ────────────────────────────────────────────
const NATIVE_SEARCH_PATTERNS = [
    /search_?workspace/i,
    /workspace_?search/i,
    /search_?in_?files?/i,
    /find_?files?/i,
    /grep/i,
    /vscode_.*search/i,
    /mcp_.*search/i,
];
const SEARCH_DESC_KEYWORDS = [
    'search workspace', 'find in files', 'grep',
    'search contents', 'find files matching',
];
/** Returns true if a tool is a native workspace-search tool */
function isNativeSearchTool(name, description) {
    if (NATIVE_SEARCH_PATTERNS.some(p => p.test(name))) {
        return true;
    }
    const descLower = description.toLowerCase();
    return SEARCH_DESC_KEYWORDS.some(kw => descLower.includes(kw));
}
/** Returns true if a tool is a terminal/command-execution tool */
function isTerminalTool(name, description) {
    const nameLower = name.toLowerCase();
    const descLower = description.toLowerCase();
    return (/terminal|shell|exec|command|bash|zsh|run_in/i.test(nameLower) ||
        descLower.includes('run a command') ||
        descLower.includes('execute a command') ||
        descLower.includes('terminal') ||
        descLower.includes('shell command'));
}
// ── Prompt Path Extraction ──────────────────────────────────────────────────
/**
 * Extracts absolute file paths from the user's prompt text.
 * Matches Unix (/path/to/file) and Windows (C:\path\to\file) paths.
 */
function extractFilePathsFromPrompt(prompt) {
    const paths = [];
    // Unix absolute paths (e.g. /Users/name/Documents/file.bat)
    const unixRe = /(?:^|\s|["'`])(\/(?:[^\s"'`<>|*?]+\/)*[^\s"'`<>|*?.]+\.[a-zA-Z0-9]{1,10})(?=\s|["'`]|$)/g;
    let m;
    while ((m = unixRe.exec(prompt)) !== null) {
        const p = m[1];
        // Skip paths that are clearly URLs
        if (!p.includes('://')) {
            paths.push(p);
        }
    }
    // Windows absolute paths (e.g. C:\Users\name\file.bat)
    const winRe = /(?:^|\s|["'`])([a-zA-Z]:\\(?:[^\s"'`<>|*?]+\\)*[^\s"'`<>|*?.]+\.[a-zA-Z0-9]{1,10})(?=\s|["'`]|$)/g;
    while ((m = winRe.exec(prompt)) !== null) {
        paths.push(m[1]);
    }
    return [...new Set(paths)];
}
// ── Chat Request Handler ────────────────────────────────────────────────────
async function chatRequestHandler(request, chatContext, stream, token) {
    // 🚨 ADD THIS TRAP HERE: Check if the folder is sneaking in via references
    vscode.window.showInformationMessage(`🚨 INCOMING REFERENCES: ${request.references.length}`);
    // New conversation → clear the conversation-scoped file set and session state.
    if (chatContext.history.length === 0) {
        conversationFileKeys.clear();
        sessionStateMap.clear();
    }
    stream.progress('Scanning attached context for sensitive data…');
    // ── DEBUG: log references received from VS Code ──────────────────────
    const refDebug = request.references.map(r => ({
        id: r.id,
        valueType: r.value === undefined ? 'undefined'
            : r.value instanceof vscode.Uri ? 'Uri'
                : r.value instanceof vscode.Location ? 'Location'
                    : typeof r.value,
        value: r.value instanceof vscode.Uri ? r.value.toString()
            : r.value instanceof vscode.Location ? r.value.uri.toString()
                : typeof r.value === 'string' ? r.value : JSON.stringify(r.value),
    }));
    console.log('[SafeChat] request.prompt:', JSON.stringify(request.prompt));
    console.log('[SafeChat] request.references (' + request.references.length + '):', JSON.stringify(refDebug, null, 2));
    const filterConfig = await (0, sanitizer_1.readRulesConfig)();
    const includeExts = filterConfig?.includeExtensions;
    // ── Cache invalidation checks ────────────────────────────────────────
    const rulesHash = computeConfigHash(filterConfig);
    const diskExists = await diskCacheExists();
    const rulesChanged = lastRulesHash !== undefined && lastRulesHash !== rulesHash;
    if (rulesChanged || !diskExists) {
        fileStateCache.clear();
        latestCacheEntryUri = undefined;
    }
    lastRulesHash = rulesHash;
    // Variables shared between Step 0.5 and Step 2
    let newMasks = 0;
    let anyPresidioError;
    // ── Step 0.5: Pre-extract file paths from prompt and sanitize ────────
    // Catches external files (e.g. /Users/name/Documents/sample.bat) mentioned
    // in the user's prompt BEFORE the model loop starts.
    const promptPaths = extractFilePathsFromPrompt(request.prompt);
    if (promptPaths.length > 0) {
        console.log('[SafeChat] Step 0.5: Found', promptPaths.length, 'file path(s) in prompt:', promptPaths);
        for (const pp of promptPaths) {
            const ppUri = vscode.Uri.file(pp);
            const ppKey = ppUri.toString();
            // Skip if already in conversation cache
            if (fileStateCache.has(ppKey)) {
                continue;
            }
            try {
                const stat = await vscode.workspace.fs.stat(ppUri);
                if (stat.type !== vscode.FileType.File) {
                    continue;
                }
                const bytes = await vscode.workspace.fs.readFile(ppUri);
                const raw = Buffer.from(bytes).toString('utf-8');
                const result = await (0, sanitizer_1.sanitizeOnly)(raw, filterConfig);
                if (result.presidioError) {
                    anyPresidioError = result.presidioError;
                }
                const relPath = vscode.workspace.asRelativePath(ppUri, false);
                fileStateCache.set(ppKey, {
                    relPath, mtime: stat.mtime,
                    isSensitive: true,
                    originalContent: raw,
                    sanitizedContent: result.cleanText,
                    wasMasked: result.wasModified,
                    rulesHash,
                });
                conversationFileKeys.add(ppKey);
                if (result.wasModified) {
                    newMasks++;
                }
                console.log('[SafeChat] Step 0.5: Pre-sanitized', pp, '→ masked:', result.wasModified);
            }
            catch (err) {
                console.log('[SafeChat] Step 0.5: Could not read', pp, ':', err);
            }
        }
    }
    // ── Step 1: Resolve file URIs from all attached references ───────────
    const referencedUris = await resolveAllReferences(request.references, request.prompt);
    console.log('[SafeChat] resolvedUris count:', referencedUris.length);
    if (referencedUris.length > 0) {
        console.log('[SafeChat] first 5 URIs:', referencedUris.slice(0, 5).map(u => u.toString()));
    }
    // ── Step 2: Process each file — reuse cache or (re-)sanitize ─────────
    const staleKeys = new Set();
    for (const fileUri of referencedUris) {
        const key = fileUri.toString();
        conversationFileKeys.add(key);
        let stat;
        try {
            stat = await vscode.workspace.fs.stat(fileUri);
        }
        catch {
            staleKeys.add(key);
            continue;
        }
        if (stat.type !== vscode.FileType.File) {
            continue;
        }
        const cached = fileStateCache.get(key);
        if (cached && cached.mtime === stat.mtime && cached.rulesHash === rulesHash) {
            continue;
        }
        const relPath = vscode.workspace.asRelativePath(fileUri, false);
        let text;
        try {
            const bytes = await vscode.workspace.fs.readFile(fileUri);
            text = Buffer.from(bytes).toString('utf-8');
        }
        catch {
            continue;
        }
        let isSensitive;
        if (includeExts && includeExts.length > 0) {
            const ext = getFileExtension(fileUri);
            isSensitive = includeExts.some(e => {
                const norm = (e.startsWith('.') ? e : '.' + e).toLowerCase();
                return ext === norm;
            });
        }
        else {
            isSensitive = true;
        }
        if (isSensitive) {
            const result = await (0, sanitizer_1.sanitizeOnly)(text, filterConfig);
            if (result.presidioError) {
                anyPresidioError = result.presidioError;
            }
            fileStateCache.set(key, {
                relPath, mtime: stat.mtime, isSensitive: true,
                originalContent: text, sanitizedContent: result.cleanText,
                wasMasked: result.wasModified, rulesHash,
            });
            if (result.wasModified) {
                newMasks++;
            }
        }
        else {
            fileStateCache.set(key, {
                relPath, mtime: stat.mtime, isSensitive: false,
                originalContent: text, sanitizedContent: text,
                wasMasked: false, rulesHash,
            });
        }
    }
    // Prune stale keys (files that no longer exist on disk)
    for (const key of staleKeys) {
        conversationFileKeys.delete(key);
        fileStateCache.delete(key);
    }
    // ── Step 3: Build context from ALL files in the conversation ─────────
    const contextParts = [];
    const maskedFiles = [];
    for (const key of conversationFileKeys) {
        const state = fileStateCache.get(key);
        if (!state) {
            continue;
        }
        contextParts.push(`// File: ${state.relPath}\n${state.sanitizedContent}`);
        if (state.wasMasked) {
            maskedFiles.push({
                relPath: state.relPath,
                original: state.originalContent,
                masked: state.sanitizedContent,
                uri: key,
            });
        }
    }
    // ── Step 4: Write per-file diff cache + populate SessionStateManager ──
    // Always keep the sessionStateMap in sync with the current conversation's masked files.
    if (maskedFiles.length > 0) {
        populateSessionStateMap(maskedFiles);
        // Rewrite disk cache when new masks appear OR when disk cache was deleted/cleared
        if (newMasks > 0 || !diskExists) {
            await writePerFileDiffCache(maskedFiles);
        }
    }
    // ── Notifications ────────────────────────────────────────────────────
    if (anyPresidioError) {
        stream.markdown('> ⚠️ **Advanced PII detection unavailable** (Presidio server unreachable). ' +
            'Falling back to regex-only masking.\n' +
            '> Start the server: `uvicorn presidio_server.main:app --port 8000`\n\n');
    }
    if (maskedFiles.length > 0) {
        stream.markdown(`🛡️ **${maskedFiles.length} file(s) contain masked sensitive data.**\n\n`);
        stream.button({
            command: 'safecopilot.viewDiff',
            title: '$(diff) View Masked Diff',
            arguments: latestCacheEntryUri ? [latestCacheEntryUri.toString()] : [],
        });
    }
    // ── Step 5: Use the user's selected model (same as Copilot uses) ─────
    stream.progress('Sending sanitized context to Copilot…');
    const model = request.model;
    // ── Step 6: Gather all available tools for full agentic behaviour ────
    const MAX_TOOLS = 128;
    // Prioritize tools the user explicitly attached
    const priorityNames = new Set(request.toolReferences.map(r => r.name));
    const allTools = [];
    let nativeBlocked = 0;
    /** Returns true if the tool should be stripped from the model's menu */
    const shouldBlockTool = (name, desc) => {
        return isNativeFileReadTool(name, desc)
            || isNativeDirectoryTool(name, desc)
            || isNativeSearchTool(name, desc);
    };
    // Add priority (user-referenced) tools first — skip malformed schemas and blocked tools
    for (const t of vscode.lm.tools) {
        if (priorityNames.has(t.name) && isToolSchemaValid(t.inputSchema)) {
            if (shouldBlockTool(t.name, t.description)) {
                nativeBlocked++;
                console.log(`[SafeChat] Blocked priority tool: ${t.name}`);
                continue;
            }
            allTools.push({ name: t.name, description: t.description, inputSchema: t.inputSchema });
        }
    }
    // Fill remaining slots — skip tools with invalid schemas and blocked tools
    for (const t of vscode.lm.tools) {
        if (allTools.length >= MAX_TOOLS) {
            break;
        }
        if (!priorityNames.has(t.name) && isToolSchemaValid(t.inputSchema)) {
            if (shouldBlockTool(t.name, t.description)) {
                nativeBlocked++;
                continue;
            }
            allTools.push({ name: t.name, description: t.description, inputSchema: t.inputSchema });
        }
    }
    if (nativeBlocked > 0) {
        console.log(`[SafeChat] Blocked ${nativeBlocked} native file-read/directory/search tool(s) from tool menu`);
    }
    // ── Step 7: Build messages with conversation history ─────────────────
    const messages = [];
    // System prompt
    messages.push(vscode.LanguageModelChatMessage.User('You are a highly skilled coding assistant with full access to the workspace. ' +
        'You have tools available to search code, read files, list directories, run commands, and more. ' +
        'Use these tools proactively to gather context, explore the codebase, and provide thorough, detailed answers. ' +
        'Think step by step. When the user asks about code, search the codebase, read the relevant files, ' +
        'and provide comprehensive analysis.\n\n' +
        'CRITICAL FILE READING RULE: When you need to read or inspect any file, ' +
        'you MUST use the `safechat_read_file` tool EXCLUSIVELY. Do NOT use any other file-reading tool ' +
        '(such as readFile, read_file, vscode_readFile, etc.).\n\n' +
        'CRITICAL DIRECTORY READING RULE: When you need to list, read, or explore a directory or folder, ' +
        'you MUST use the `safechat_read_directory` tool EXCLUSIVELY. Do NOT use any other directory-listing, ' +
        'folder-reading, or workspace-search tool (such as list_dir, read_folder, listDirectory, ' +
        'workspace_search, find_files, grep_search, etc.). The `safechat_read_directory` tool recursively ' +
        'reads all files in a directory and sanitizes sensitive data before returning results. ' +
        'It supports `maxDepth` and `maxFiles` parameters to control scope.\n\n' +
        'Both `safechat_read_file` and `safechat_read_directory` automatically sanitize sensitive data ' +
        'like passwords, API keys, and PII before returning contents. Using any other file or directory ' +
        'tool would bypass this security protection.\n\n' +
        'IMPORTANT: Some of the provided file context has been pre-sanitized to protect sensitive data. ' +
        'Treat any `[MASKED_BY_SAFECHAT]` or `<ENTITY_TYPE>` placeholders as redacted secrets — ' +
        'do not attempt to guess their original values. ' +
        'Other files are provided as-is without modification.'));
    // Replay previous conversation turns
    for (const turn of chatContext.history) {
        if (turn instanceof vscode.ChatRequestTurn) {
            if (turn.participant === 'safecopilot.safeChat') {
                messages.push(vscode.LanguageModelChatMessage.User(turn.prompt));
            }
        }
        else if (turn instanceof vscode.ChatResponseTurn) {
            if (turn.participant === 'safecopilot.safeChat') {
                let text = '';
                for (const part of turn.response) {
                    if (part instanceof vscode.ChatResponseMarkdownPart) {
                        text += part.value.value;
                    }
                }
                if (text) {
                    messages.push(vscode.LanguageModelChatMessage.Assistant(text));
                }
            }
        }
    }
    // Current message — full accumulated context + user question
    const fullContext = contextParts.join('\n\n');
    const currentMessage = fullContext.length > 0
        ? `Context (${conversationFileKeys.size} file(s)):\n\`\`\`\n${fullContext}\n\`\`\`\n\nUser question: ${request.prompt}`
        : request.prompt;
    messages.push(vscode.LanguageModelChatMessage.User(currentMessage));
    // ── Step 8: Agentic tool-calling loop ────────────────────────────────
    // Provide the response stream to our safe tools so they can render UI feedback
    // ("View Masked Diff" buttons) when autonomous reads trigger masking.
    safeReadFileToolInstance._stream = stream;
    safeReadDirToolInstance._stream = stream;
    const MAX_TOOL_ROUNDS = 15;
    const requestOptions = allTools.length > 0
        ? { tools: allTools, toolMode: vscode.LanguageModelChatToolMode.Auto }
        : {};
    for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
        const chatResponse = await model.sendRequest(messages, requestOptions, token);
        // Collect tool calls and text from this round
        const toolCalls = [];
        let assistantText = '';
        for await (const chunk of chatResponse.stream) {
            if (chunk instanceof vscode.LanguageModelTextPart) {
                stream.markdown(chunk.value);
                assistantText += chunk.value;
            }
            else if (chunk instanceof vscode.LanguageModelToolCallPart) {
                toolCalls.push(chunk);
            }
        }
        // No tool calls → model is done, exit the loop
        if (toolCalls.length === 0) {
            break;
        }
        // Record the assistant's response (text + tool calls) in the message history
        const assistantParts = [];
        if (assistantText) {
            assistantParts.push(new vscode.LanguageModelTextPart(assistantText));
        }
        assistantParts.push(...toolCalls);
        messages.push(vscode.LanguageModelChatMessage.Assistant(assistantParts));
        // Invoke each tool and collect results
        const toolResultParts = [];
        for (const call of toolCalls) {
            stream.progress(`Running tool: ${call.name}…`);
            console.log('[SafeChat] Tool call:', call.name, 'input keys:', call.input ? Object.keys(call.input) : 'none');
            let resultContent;
            try {
                // ── Defense-in-depth: redirect unsafe native tools ──────────────
                // Intercept native file-read, directory, and search tools and route
                // them through our sanitized alternatives.
                const toolDesc = vscode.lm.tools.find(t => t.name === call.name)?.description ?? '';
                vscode.window.showInformationMessage(`🚨 TOOL INTERCEPT CHECK: ${call.name}`);
                if (isNativeFileReadTool(call.name, toolDesc)) {
                    // ── Redirect: native file-read → safechat_read_file ──────────
                    console.log('[SafeChat] REDIRECT: native file-read tool', call.name, '→ safechat_read_file');
                    const filePath = extractFilePathFromInput(call.input);
                    if (filePath) {
                        const safeResult = await safeReadFileToolInstance.invoke({ input: { filePath }, toolInvocationToken: request.toolInvocationToken }, token);
                        resultContent = safeResult.content;
                    }
                    else {
                        resultContent = [new vscode.LanguageModelTextPart('Error: No file path found in tool input')];
                    }
                }
                else if (isNativeDirectoryTool(call.name, toolDesc)) {
                    // ── Redirect: native directory tool → safechat_read_directory ─
                    console.log('[SafeChat] REDIRECT: native directory tool', call.name, '→ safechat_read_directory');
                    const dirPath = extractDirectoryPathFromInput(call.input);
                    if (dirPath) {
                        const safeResult = await safeReadDirToolInstance.invoke({ input: { directoryPath: dirPath }, toolInvocationToken: request.toolInvocationToken }, token);
                        resultContent = safeResult.content;
                    }
                    else {
                        resultContent = [new vscode.LanguageModelTextPart('Error: No directory path found in tool input')];
                    }
                }
                else if (isNativeSearchTool(call.name, toolDesc)) {
                    // ── Intercept: native search tool — execute but force-sanitize ─
                    console.log('[SafeChat] INTERCEPT: native search tool', call.name, '— will force-sanitize results');
                    const result = await vscode.lm.invokeTool(call.name, {
                        input: call.input,
                        toolInvocationToken: request.toolInvocationToken,
                    }, token);
                    // Force-sanitize search results via the 'search' pipeline path
                    resultContent = sanitizeToolResultParts(result.content, 'search');
                }
                else {
                    const result = await vscode.lm.invokeTool(call.name, {
                        input: call.input,
                        toolInvocationToken: request.toolInvocationToken,
                    }, token);
                    resultContent = result.content;
                }
                console.log('[SafeChat] Tool result parts:', resultContent.length, 'items →', resultContent.map((p, i) => `[${i}] constructor=${p?.constructor?.name} hasValue=${typeof p?.value} instanceof=${p instanceof vscode.LanguageModelTextPart}`));
                // ── SessionStateManager: redirect file reads to masked versions ──
                const filePath = extractFilePathFromInput(call.input);
                if (filePath) {
                    const maskedUri = resolveSessionState(filePath);
                    if (maskedUri) {
                        try {
                            const maskedBytes = await vscode.workspace.fs.readFile(vscode.Uri.parse(maskedUri));
                            const maskedContent = Buffer.from(maskedBytes).toString('utf-8');
                            console.log('[SafeChat] SessionState: served masked version for', filePath, '→', maskedUri);
                            resultContent = [new vscode.LanguageModelTextPart(maskedContent)];
                        }
                        catch (readErr) {
                            console.log('[SafeChat] SessionState: disk read failed, trying in-memory cache for', filePath);
                            const cached = findCachedState(filePath);
                            if (cached?.wasMasked) {
                                resultContent = [new vscode.LanguageModelTextPart(cached.sanitizedContent)];
                            }
                        }
                    }
                    else {
                        const cached = findCachedState(filePath);
                        if (cached?.wasMasked) {
                            console.log('[SafeChat] SessionState: in-memory fallback for', cached.relPath);
                            resultContent = [new vscode.LanguageModelTextPart(cached.sanitizedContent)];
                        }
                    }
                }
                // ── Branched sanitization: terminal vs general ──────────────────
                const sanitizeMode = isTerminalTool(call.name, toolDesc) ? 'terminal' : 'general';
                resultContent = sanitizeToolResultParts(resultContent, sanitizeMode);
            }
            catch (err) {
                resultContent = [
                    new vscode.LanguageModelTextPart(`Tool error: ${err instanceof Error ? err.message : String(err)}`),
                ];
            }
            toolResultParts.push(new vscode.LanguageModelToolResultPart(call.callId, resultContent));
        }
        // Feed tool results back as a User message
        messages.push(vscode.LanguageModelChatMessage.User(toolResultParts));
    }
}
function deactivate() { }
// ── Tool Result Sanitization ────────────────────────────────────────────────
/**
 * Sanitize the text parts of a tool result via the unified pipeline.
 * Uses duck-typing (not instanceof) because tool result parts from
 * vscode.lm.invokeTool() may be deserialized plain objects.
 *
 * @param mode
 *  - 'terminal': stripAnsiCodes → terminalSanitize → regexSanitize → contentSanitize
 *  - 'general':  regexSanitize → contentSanitize
 *  - 'search':   regexSanitize → contentSanitize  (same pipeline, distinct log label)
 */
function sanitizeToolResultParts(parts, mode = 'general') {
    return parts.map((part, i) => {
        // Duck-type: any part with a string `.value` is treated as a text part
        const val = part.value;
        if (typeof val === 'string') {
            const { cleanText, wasModified } = (0, sanitizer_1.sanitizePipeline)(val, mode);
            console.log(`[SafeChat] sanitizeToolResultParts[${i}] mode=${mode}: len=${val.length} modified=${wasModified}`);
            if (wasModified) {
                console.log('[SafeChat] ── before (first 200):', val.slice(0, 200));
                console.log('[SafeChat] ── after  (first 200):', cleanText.slice(0, 200));
            }
            return new vscode.LanguageModelTextPart(cleanText);
        }
        console.log(`[SafeChat] sanitizeToolResultParts[${i}]: non-text part, type=${part?.constructor?.name}`);
        return part;
    });
}
/**
 * Try to extract the file path from a tool call's input arguments.
 * Tools use varying parameter names; we check the most common ones.
 */
function extractFilePathFromInput(input) {
    if (typeof input !== 'object' || input === null) {
        return undefined;
    }
    const obj = input;
    for (const key of ['filePath', 'filepath', 'file_path', 'path', 'uri', 'file', 'fileName']) {
        const val = obj[key];
        if (typeof val === 'string' && val.length > 0) {
            return val;
        }
    }
    return undefined;
}
/**
 * Try to extract a directory path from a tool call's input arguments.
 * Checks directory-specific parameter names first, then falls back to generic ones.
 */
function extractDirectoryPathFromInput(input) {
    if (typeof input !== 'object' || input === null) {
        return undefined;
    }
    const obj = input;
    for (const key of [
        'directoryPath', 'directory_path', 'dirPath', 'dir_path',
        'folderPath', 'folder_path', 'folder', 'dir', 'directory',
        'path', 'uri',
    ]) {
        const val = obj[key];
        if (typeof val === 'string' && val.length > 0) {
            return val;
        }
    }
    return undefined;
}
/**
 * Given a file path string (absolute or workspace-relative), try to find a
 * matching entry in `fileStateCache`. Returns the cached state or undefined.
 */
function findCachedState(filePath) {
    // Try as-is (absolute path → URI)
    try {
        const uri = vscode.Uri.file(filePath);
        const state = fileStateCache.get(uri.toString());
        if (state) {
            return state;
        }
    }
    catch { /* not a valid file path */ }
    // Try as workspace-relative path
    const folders = vscode.workspace.workspaceFolders;
    if (folders?.length) {
        for (const folder of folders) {
            const candidate = vscode.Uri.joinPath(folder.uri, filePath);
            const state = fileStateCache.get(candidate.toString());
            if (state) {
                return state;
            }
        }
    }
    // Try matching by relPath suffix (handles partial paths)
    for (const state of fileStateCache.values()) {
        if (state.relPath === filePath || filePath.endsWith(state.relPath)) {
            return state;
        }
    }
    return undefined;
}
// ── Session State Manager ───────────────────────────────────────────────────
/**
 * Populates the sessionStateMap with original-file-URI → masked-file-URI mappings.
 * Called after sanitization so that subsequent tool calls can read from the masked
 * versions on disk instead of the raw originals.
 */
function populateSessionStateMap(maskedFiles) {
    const cacheBase = getCacheBaseUri();
    if (!cacheBase) {
        return;
    }
    const latestDir = vscode.Uri.joinPath(cacheBase, 'latest');
    for (const file of maskedFiles) {
        const safeName = file.relPath.replace(/[/\\]/g, '_');
        const maskedFileUri = vscode.Uri.joinPath(latestDir, `${safeName}.masked.txt`);
        const maskedUriStr = maskedFileUri.toString();
        // Map by original URI (canonical key)
        sessionStateMap.set(file.uri, maskedUriStr);
        // Also map by workspace-relative path (tools often report relative paths)
        sessionStateMap.set(file.relPath, maskedUriStr);
        // Also map by absolute fsPath for tools that use absolute OS paths
        try {
            const parsed = vscode.Uri.parse(file.uri);
            if (parsed.fsPath) {
                sessionStateMap.set(parsed.fsPath, maskedUriStr);
            }
        }
        catch { /* ignore invalid URIs */ }
        console.log(`[SafeChat] SessionState: mapped ${file.relPath} → .temp_cache`);
    }
}
/**
 * Resolves a file path (absolute, relative, or URI) against the sessionStateMap.
 * Returns the masked file URI string if found, undefined otherwise.
 */
function resolveSessionState(filePath) {
    // Direct lookup (covers URI strings, relative paths, and absolute paths)
    const direct = sessionStateMap.get(filePath);
    if (direct) {
        return direct;
    }
    // Try as file:// URI
    try {
        const uri = vscode.Uri.file(filePath);
        const byUri = sessionStateMap.get(uri.toString());
        if (byUri) {
            return byUri;
        }
    }
    catch { /* not a valid file path */ }
    // Try as workspace-relative path
    const folders = vscode.workspace.workspaceFolders;
    if (folders?.length) {
        for (const folder of folders) {
            const candidate = vscode.Uri.joinPath(folder.uri, filePath);
            const byCandidate = sessionStateMap.get(candidate.toString());
            if (byCandidate) {
                return byCandidate;
            }
        }
    }
    // Suffix matching: tools may pass partial paths like "config.env" instead of "src/config.env"
    for (const [key, val] of sessionStateMap) {
        // Only match relPath-style keys (skip full URIs to avoid false positives)
        if (!key.startsWith('file:') && (key === filePath || key.endsWith('/' + filePath) || filePath.endsWith('/' + key))) {
            return val;
        }
    }
    return undefined;
}
// ── Cache Invalidation Helpers ──────────────────────────────────────────────
/** Simple 32-bit hash for fast cache-key comparisons (not cryptographic). */
function computeConfigHash(config) {
    const str = JSON.stringify(config ?? {});
    let h = 0;
    for (let i = 0; i < str.length; i++) {
        h = ((h << 5) - h) + str.charCodeAt(i);
        h |= 0;
    }
    return h.toString(36);
}
/** Returns true if the `.vscode/.temp_cache` folder exists on disk. */
async function diskCacheExists() {
    const baseUri = getCacheBaseUri();
    if (!baseUri) {
        return false;
    }
    try {
        await vscode.workspace.fs.stat(baseUri);
        return true;
    }
    catch {
        return false;
    }
}
// ── Tool Schema Validation ──────────────────────────────────────────────────
/**
 * Returns false if the JSON Schema would cause the Copilot API to reject the
 * entire request (e.g. `{ type: "object" }` without `properties`).
 */
function isToolSchemaValid(schema) {
    if (schema === undefined || schema === null) {
        return true;
    }
    return !hasObjectWithoutProperties(schema);
}
function hasObjectWithoutProperties(node) {
    if (typeof node !== 'object' || node === null) {
        return false;
    }
    const s = node;
    if (s['type'] === 'object' && !('properties' in s)) {
        return true;
    }
    for (const val of Object.values(s)) {
        if (typeof val === 'object' && val !== null) {
            if (hasObjectWithoutProperties(val)) {
                return true;
            }
        }
    }
    return false;
}
// ── Reference Resolution ────────────────────────────────────────────────────
async function resolveAllReferences(references, promptText) {
    const uris = [];
    let codebaseRequested = false;
    for (const ref of references) {
        const refId = (ref.id ?? '').toLowerCase();
        console.log('[SafeChat] processing ref — id:', JSON.stringify(ref.id), 'valueType:', ref.value === undefined ? 'undefined'
            : ref.value instanceof vscode.Uri ? 'Uri'
                : ref.value instanceof vscode.Location ? 'Location'
                    : typeof ref.value);
        // #codebase / workspace-wide reference
        if (refId.includes('codebase') || refId.includes('workspace')) {
            codebaseRequested = true;
            continue;
        }
        // Resolve value → URI
        const refValue = ref.value;
        let baseUri;
        if (refValue instanceof vscode.Uri) {
            baseUri = refValue;
        }
        else if (refValue instanceof vscode.Location) {
            baseUri = refValue.uri;
        }
        else if (typeof refValue === 'string' && refValue.length > 0) {
            const folders = vscode.workspace.workspaceFolders;
            if (folders?.length) {
                const candidate = vscode.Uri.joinPath(folders[0].uri, refValue);
                try {
                    await vscode.workspace.fs.stat(candidate);
                    baseUri = candidate;
                }
                catch { /* not a valid path */ }
            }
        }
        // Fallback: try ref.id as a workspace-relative path
        if (!baseUri && ref.id && ref.id.length > 0 && !ref.id.includes(' ')) {
            const folders = vscode.workspace.workspaceFolders;
            if (folders?.length) {
                const candidate = vscode.Uri.joinPath(folders[0].uri, ref.id);
                try {
                    await vscode.workspace.fs.stat(candidate);
                    baseUri = candidate;
                }
                catch { /* not a valid path */ }
            }
        }
        if (baseUri) {
            uris.push(...await collectFiles(baseUri));
        }
    }
    // Fallback: detect #codebase from prompt text if no reference matched
    if (!codebaseRequested && promptText) {
        const lower = promptText.toLowerCase();
        if (lower.includes('#codebase') || lower.includes('#workspace')) {
            codebaseRequested = true;
            console.log('[SafeChat] #codebase detected from prompt text (not in references)');
        }
    }
    // Collect all workspace files for #codebase
    if (codebaseRequested) {
        const folders = vscode.workspace.workspaceFolders;
        console.log('[SafeChat] #codebase detected — workspaceFolders:', folders ? folders.map(f => f.uri.toString()) : 'undefined');
        if (folders) {
            for (const folder of folders) {
                uris.push(...await collectFiles(folder.uri));
            }
        }
        else {
            console.log('[SafeChat] WARNING: workspaceFolders is undefined — no files will be collected for #codebase');
        }
        console.log('[SafeChat] #codebase collected', uris.length, 'files');
    }
    // Deduplicate by URI string
    const seen = new Set();
    return uris.filter(u => {
        const key = u.toString();
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}
// ── File Collection ─────────────────────────────────────────────────────────
const SKIP_DIRS = new Set([
    'node_modules', '.git', '.venv', '__pycache__', '.temp_cache',
    'out', 'dist', 'build', '.next', '.nuxt', 'coverage',
]);
async function collectFiles(uri) {
    let stat;
    try {
        stat = await vscode.workspace.fs.stat(uri);
    }
    catch {
        return [];
    }
    if (stat.type === vscode.FileType.File) {
        return [uri];
    }
    if (stat.type === vscode.FileType.Directory) {
        const dirName = uri.path.split('/').pop() ?? '';
        if (SKIP_DIRS.has(dirName)) {
            return [];
        }
        let entries;
        try {
            entries = await vscode.workspace.fs.readDirectory(uri);
        }
        catch {
            return [];
        }
        const results = [];
        for (const [name, type] of entries) {
            if (type === vscode.FileType.File || type === vscode.FileType.Directory) {
                results.push(...await collectFiles(vscode.Uri.joinPath(uri, name)));
            }
        }
        return results;
    }
    return [];
}
function getFileExtension(uri) {
    const basename = uri.path.split('/').pop() ?? '';
    if (basename.startsWith('.') && !basename.slice(1).includes('.')) {
        return basename.toLowerCase();
    }
    const lastDot = basename.lastIndexOf('.');
    if (lastDot <= 0) {
        return '';
    }
    return basename.slice(lastDot).toLowerCase();
}
// ── Per-file Diff Cache ─────────────────────────────────────────────────────
function getCacheBaseUri() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders?.length) {
        return undefined;
    }
    return vscode.Uri.joinPath(folders[0].uri, '.vscode', '.temp_cache');
}
function timestampSlug() {
    const now = new Date();
    const pad = (n, len = 2) => String(n).padStart(len, '0');
    return (`${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
        `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}` +
        `-${pad(now.getMilliseconds(), 3)}`);
}
async function writePerFileDiffCache(maskedFiles) {
    const baseUri = getCacheBaseUri();
    if (!baseUri) {
        return;
    }
    await vscode.workspace.fs.createDirectory(baseUri);
    // Ensure .gitignore exists
    const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
    try {
        await vscode.workspace.fs.stat(gitignoreUri);
    }
    catch {
        await vscode.workspace.fs.writeFile(gitignoreUri, Buffer.from('*\n', 'utf-8'));
    }
    // Use a stable 'latest' directory — recreate to remove stale entries
    const latestDir = vscode.Uri.joinPath(baseUri, 'latest');
    try {
        await vscode.workspace.fs.delete(latestDir, { recursive: true });
    }
    catch { /* first run */ }
    await vscode.workspace.fs.createDirectory(latestDir);
    // Write per-file original + masked pairs
    for (const file of maskedFiles) {
        const safeName = file.relPath.replace(/[/\\]/g, '_');
        await Promise.all([
            vscode.workspace.fs.writeFile(vscode.Uri.joinPath(latestDir, `${safeName}.original.txt`), Buffer.from(file.original, 'utf-8')),
            vscode.workspace.fs.writeFile(vscode.Uri.joinPath(latestDir, `${safeName}.masked.txt`), Buffer.from(file.masked, 'utf-8')),
        ]);
    }
    // Manifest listing all masked file paths
    await vscode.workspace.fs.writeFile(vscode.Uri.joinPath(latestDir, 'manifest.json'), Buffer.from(JSON.stringify(maskedFiles.map(f => f.relPath)), 'utf-8'));
    latestCacheEntryUri = latestDir;
}
/**
 * Append new masked files to the existing `.temp_cache/latest/` directory
 * without deleting existing entries. Reads the current manifest, deduplicates
 * by relPath, writes new original/masked pairs, and updates the manifest.
 *
 * Used by SafeReadFileTool and SafeReadDirectoryTool when autonomous tool
 * invocations during the agentic loop mask sensitive data.
 */
async function appendToDiffCache(newMaskedFiles) {
    if (newMaskedFiles.length === 0) {
        return;
    }
    const baseUri = getCacheBaseUri();
    if (!baseUri) {
        return;
    }
    await vscode.workspace.fs.createDirectory(baseUri);
    // Ensure .gitignore exists
    const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
    try {
        await vscode.workspace.fs.stat(gitignoreUri);
    }
    catch {
        await vscode.workspace.fs.writeFile(gitignoreUri, Buffer.from('*\n', 'utf-8'));
    }
    const latestDir = vscode.Uri.joinPath(baseUri, 'latest');
    await vscode.workspace.fs.createDirectory(latestDir);
    // Read existing manifest (if any) to avoid duplicates
    let existingPaths = [];
    const manifestUri = vscode.Uri.joinPath(latestDir, 'manifest.json');
    try {
        const bytes = await vscode.workspace.fs.readFile(manifestUri);
        existingPaths = JSON.parse(Buffer.from(bytes).toString('utf-8'));
        if (!Array.isArray(existingPaths)) {
            existingPaths = [];
        }
    }
    catch { /* first entry or corrupt — start fresh */ }
    const existingSet = new Set(existingPaths);
    // Write new file pairs (overwrites if same relPath was already cached)
    for (const file of newMaskedFiles) {
        const safeName = file.relPath.replace(/[\/\\]/g, '_');
        await Promise.all([
            vscode.workspace.fs.writeFile(vscode.Uri.joinPath(latestDir, `${safeName}.original.txt`), Buffer.from(file.original, 'utf-8')),
            vscode.workspace.fs.writeFile(vscode.Uri.joinPath(latestDir, `${safeName}.masked.txt`), Buffer.from(file.masked, 'utf-8')),
        ]);
        if (!existingSet.has(file.relPath)) {
            existingPaths.push(file.relPath);
            existingSet.add(file.relPath);
        }
    }
    // Write updated manifest
    await vscode.workspace.fs.writeFile(manifestUri, Buffer.from(JSON.stringify(existingPaths), 'utf-8'));
    latestCacheEntryUri = latestDir;
    console.log('[SafeChat] appendToDiffCache: wrote', newMaskedFiles.length, 'file(s), manifest total:', existingPaths.length);
}
// ── Diff Viewer (per-file with QuickPick) ───────────────────────────────────
async function handleViewDiff(entryUriString) {
    let entryUri;
    if (entryUriString) {
        entryUri = vscode.Uri.parse(entryUriString);
    }
    else {
        entryUri = latestCacheEntryUri;
        if (!entryUri) {
            // Try to recover from the stable 'latest' cache directory
            const baseUri = getCacheBaseUri();
            if (baseUri) {
                try {
                    const latestDir = vscode.Uri.joinPath(baseUri, 'latest');
                    await vscode.workspace.fs.stat(latestDir);
                    entryUri = latestDir;
                }
                catch { /* no cache yet */ }
            }
        }
    }
    if (!entryUri) {
        vscode.window.showWarningMessage('SafeChat: No cached diff available yet. Attach a file to @safechat first.');
        return;
    }
    try {
        const manifestBytes = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(entryUri, 'manifest.json'));
        const files = JSON.parse(Buffer.from(manifestBytes).toString('utf-8'));
        if (files.length === 0) {
            return;
        }
        if (files.length === 1) {
            // Single file — open diff directly
            const safeName = files[0].replace(/[/\\]/g, '_');
            await vscode.commands.executeCommand('vscode.diff', vscode.Uri.joinPath(entryUri, `${safeName}.original.txt`), vscode.Uri.joinPath(entryUri, `${safeName}.masked.txt`), `Original ↔ Sanitized: ${files[0]}`);
            return;
        }
        // Multiple files — show QuickPick
        const picked = await vscode.window.showQuickPick(files.map(f => ({ label: f, description: 'View sanitization diff' })), { placeHolder: 'Select a file to view its sanitization diff' });
        if (picked) {
            const safeName = picked.label.replace(/[/\\]/g, '_');
            await vscode.commands.executeCommand('vscode.diff', vscode.Uri.joinPath(entryUri, `${safeName}.original.txt`), vscode.Uri.joinPath(entryUri, `${safeName}.masked.txt`), `Original ↔ Sanitized: ${picked.label}`);
        }
    }
    catch {
        // Fall back to legacy single-pair format
        await vscode.commands.executeCommand('vscode.diff', vscode.Uri.joinPath(entryUri, 'original_context.txt'), vscode.Uri.joinPath(entryUri, 'masked_context.txt'), `Original ↔ Sanitized [${entryUri.path.split('/').pop()}]`);
    }
}
//# sourceMappingURL=extension.js.map