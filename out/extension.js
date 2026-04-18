"use strict";
/**
 * extension.ts — Smart Proxy: Universal Interceptor + Context Router
 * ═══════════════════════════════════════════════════════════════════
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
exports.proxyLog = void 0;
exports.activate = activate;
const vscode = __importStar(require("vscode"));
const yaml = __importStar(require("yaml"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const sanitizer_1 = require("./sanitizer");
// ────────────────────────────────────────────────────────────────────────────
// Permanent Disk Logging
// ────────────────────────────────────────────────────────────────────────────
function writeAuditToDisk(receiptText) {
    if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
        return;
    }
    const workspaceRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
    const auditDir = path.join(workspaceRoot, '.safechat');
    const auditFile = path.join(auditDir, 'audit.log');
    try {
        if (!fs.existsSync(auditDir)) {
            fs.mkdirSync(auditDir, { recursive: true });
        }
        fs.appendFileSync(auditFile, receiptText + '\n');
    }
    catch (err) {
        console.error('[SafeChat] Failed to write to audit log:', err);
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Write-Guard & Extension Utils
// ────────────────────────────────────────────────────────────────────────────
const WRITE_TOOL_PATTERNS = [
    /^vscode_applyWorkspaceEdit$/i, /^apply_workspace_edit$/i, /^apply_edit$/i,
    /^edit_file$/i, /^write_file$/i, /^create_file$/i, /^insert_edit/i,
    /^replace_string/i, /^apply_diff/i, /^save_file$/i, /^overwrite_file$/i,
    /^run_command$/i, /^terminal_execute$/i, /^run_in_terminal$/i,
    /^vscode_runCommand$/i, /^exec$/i, /^execute_command$/i, /^bash$/i,
];
const WRITE_DESC_KEYWORDS = [
    'apply workspace edit', 'write to file', 'create a file', 'insert into file',
    'replace in file', 'apply changes', 'save file', 'make a code change',
    'run a command', 'execute command', 'terminal', 'shell command',
];
function isNativeWriteTool(name, description) {
    if (WRITE_TOOL_PATTERNS.some(p => p.test(name))) {
        return true;
    }
    const descLower = description.toLowerCase();
    return WRITE_DESC_KEYWORDS.some(kw => descLower.includes(kw));
}
function extractFileExtension(input) {
    if (!input || typeof input !== 'object') {
        return undefined;
    }
    const record = input;
    const pathKeys = ['uri', 'filePath', 'path', 'file', 'fileName', 'resource', 'fsPath'];
    // 1. Check standard file arguments
    for (const key of pathKeys) {
        const val = record[key];
        if (typeof val === 'string' && val.length > 0)
            return extractExtFromPath(val);
    }
    // 2. THE FIX: Parse terminal commands to extract target files (e.g., "cat .env")
    if (typeof record['command'] === 'string') {
        const parts = record['command'].split(/\s+/);
        for (const part of parts) {
            const ext = extractExtFromPath(part);
            if (ext)
                return ext;
        }
    }
    // 3. Deep scan for nested objects
    for (const val of Object.values(record)) {
        if (val && typeof val === 'object' && !Array.isArray(val)) {
            const nested = val;
            for (const key of pathKeys) {
                const nv = nested[key];
                if (typeof nv === 'string' && nv.length > 0)
                    return extractExtFromPath(nv);
            }
        }
    }
    return undefined;
}
function extractExtFromPath(pathStr) {
    const basename = pathStr.split(/[/\\]/).pop() ?? '';
    if (/^\.env\./i.test(basename))
        return basename.toLowerCase();
    const dotIdx = basename.lastIndexOf('.');
    if (dotIdx > 0)
        return basename.slice(dotIdx).toLowerCase();
    if (basename.startsWith('.') && basename.length > 1)
        return basename.toLowerCase();
    return undefined;
}
function extractFilePath(input) {
    if (!input || typeof input !== 'object') {
        return 'unknown context';
    }
    const record = input;
    const pathKeys = ['uri', 'filePath', 'path', 'file', 'fileName', 'resource', 'fsPath', 'command'];
    for (const key of pathKeys) {
        const val = record[key];
        if (typeof val === 'string' && val.length > 0)
            return val;
    }
    for (const val of Object.values(record)) {
        if (val && typeof val === 'object' && !Array.isArray(val)) {
            const nested = val;
            for (const key of pathKeys) {
                const nv = nested[key];
                if (typeof nv === 'string' && nv.length > 0)
                    return nv;
            }
        }
    }
    return 'unknown context';
}
// ── HELPER: Flattens VS Code's internal PromptTsx AST into raw file text ──
function flattenTsxTree(obj) {
    if (!obj || typeof obj !== 'object')
        return '';
    let text = '';
    if (typeof obj.text === 'string') {
        text += obj.text;
    }
    if (Array.isArray(obj.children)) {
        for (const child of obj.children) {
            text += flattenTsxTree(child);
        }
    }
    else {
        for (const val of Object.values(obj)) {
            if (val && typeof val === 'object') {
                text += flattenTsxTree(val);
            }
        }
    }
    return text;
}
function extractToolOutputAsString(res) {
    const parts = [];
    for (const part of res.content) {
        if (part instanceof vscode.LanguageModelTextPart) {
            parts.push(part.value);
        }
        else if (part instanceof vscode.LanguageModelPromptTsxPart) {
            // THE FIX: Flatten the AST to raw text so the Polyglot Router can actually parse it!
            const extractedText = flattenTsxTree(part.value);
            parts.push(extractedText ? extractedText : JSON.stringify(part.value, null, 2));
        }
        else {
            parts.push(String(part));
        }
    }
    return parts.join('\n');
}
// ────────────────────────────────────────────────────────────────────────────
// Dynamic Workspace Config Loader
// ────────────────────────────────────────────────────────────────────────────
async function loadWorkspaceConfig() {
    try {
        const uris = await vscode.workspace.findFiles('safechat.yml', '**/node_modules/**', 1);
        if (uris.length > 0) {
            const fileData = await vscode.workspace.fs.readFile(uris[0]);
            const text = Buffer.from(fileData).toString('utf-8');
            const parsed = yaml.parse(text);
            (0, sanitizer_1.updateConfig)(parsed);
        }
        else {
            (0, sanitizer_1.updateConfig)(null);
        }
    }
    catch (err) {
        console.error('[SafeChat] Error loading safechat.yml:', err);
        (0, sanitizer_1.updateConfig)(null);
    }
}
function activate(context) {
    exports.proxyLog = vscode.window.createOutputChannel('SafeChat Audit');
    exports.proxyLog.appendLine('[SafeChat] Smart Proxy Audit Log Initialized.');
    const participant = vscode.chat.createChatParticipant('safecopilot.safeChat', chatRequestHandler);
    participant.iconPath = new vscode.ThemeIcon('shield');
    context.subscriptions.push(participant);
    loadWorkspaceConfig();
    const watcher = vscode.workspace.createFileSystemWatcher('**/safechat.yml');
    watcher.onDidChange(() => loadWorkspaceConfig());
    watcher.onDidCreate(() => loadWorkspaceConfig());
    watcher.onDidDelete(() => {
        console.log('[SafeChat] safechat.yml deleted. Reverting to base config.');
        (0, sanitizer_1.updateConfig)(null);
    });
    context.subscriptions.push(watcher);
}
// ────────────────────────────────────────────────────────────────────────────
// The Universal Interceptor
// ────────────────────────────────────────────────────────────────────────────
async function chatRequestHandler(request, chatContext, stream, token) {
    const messages = [];
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
    messages.push(vscode.LanguageModelChatMessage.User(request.prompt));
    const model = request.model;
    const allTools = vscode.lm.tools.map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
    }));
    const requestOptions = allTools.length > 0
        ? { tools: allTools, toolMode: vscode.LanguageModelChatToolMode.Auto }
        : {};
    const MAX_TOOL_ROUNDS = 15;
    for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
        const chatResponse = await model.sendRequest(messages, requestOptions, token);
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
        if (toolCalls.length === 0) {
            break;
        }
        const assistantParts = [];
        if (assistantText) {
            assistantParts.push(new vscode.LanguageModelTextPart(assistantText));
        }
        assistantParts.push(...toolCalls);
        messages.push(vscode.LanguageModelChatMessage.Assistant(assistantParts));
        const toolResultParts = [];
        for (const call of toolCalls) {
            stream.progress(`Running tool: ${call.name}…`);
            console.log('[SafeChat] Tool call:', call.name);
            const toolDesc = vscode.lm.tools.find(t => t.name === call.name)?.description ?? '';
            if (isNativeWriteTool(call.name, toolDesc)) {
                const inputStr = JSON.stringify(call.input ?? {});
                if (inputStr.includes(sanitizer_1.MASK)) {
                    stream.markdown(`\n> ⚠️ **SafeChat Write-Guard**: Tool \`${call.name}\` was invoked ` +
                        `with input containing \`${sanitizer_1.MASK}\`. This could corrupt files or ` +
                        `execute masked credentials in the terminal. Please review the ` +
                        `operation carefully.\n\n`);
                }
            }
            let rawOutput = '';
            try {
                const result = await vscode.lm.invokeTool(call.name, { input: call.input, toolInvocationToken: request.toolInvocationToken }, token);
                rawOutput = extractToolOutputAsString(result);
            }
            catch (err) {
                rawOutput = `Error invoking tool ${call.name}: ${err instanceof Error ? err.message : String(err)}`;
            }
            // ── Context Router: extract extension → smartSanitize ──────────
            const ext = extractFileExtension(call.input);
            const { cleanText, wasModified, route, redactions } = (0, sanitizer_1.smartSanitize)(rawOutput, ext);
            if (wasModified) {
                const filename = extractFilePath(call.input);
                const uniqueRedactions = Array.from(new Set(redactions)).join(', ');
                // 1. Notify the UI
                stream.markdown(`\n🛡️ **SafeChat Proxy** (\`${route}\`): Scrubbed ${redactions.length} secrets from \`${filename}\`.\n\n`);
                // 2. Format the Receipt
                const timestamp = new Date().toISOString();
                const receiptString = `\n======================================================\n` +
                    `[AUDIT RECEIPT] 🛡️ FILE SANITIZED: ${filename}\n` +
                    `[TIMESTAMP]     ${timestamp}\n` +
                    `[ROUTE]         ${route}\n` +
                    `[SECRETS SAVED] ${redactions.length}\n` +
                    `[TYPES CAUGHT]  ${uniqueRedactions}\n` +
                    `[PAYLOAD SENT TO COPILOT]:\n\n${cleanText}\n` +
                    `======================================================\n`;
                // 3. Print to Output Channel (for live viewing)
                exports.proxyLog.appendLine(receiptString);
                // 4. Write to Hard Drive (for permanent forensic storage)
                writeAuditToDisk(receiptString);
            }
            // ── Hand sanitized result back to the LLM ─────────────────────
            toolResultParts.push(new vscode.LanguageModelToolResultPart(call.callId, [new vscode.LanguageModelTextPart(cleanText)]));
        }
        messages.push(vscode.LanguageModelChatMessage.User(toolResultParts));
    }
}
//# sourceMappingURL=extension.js.map