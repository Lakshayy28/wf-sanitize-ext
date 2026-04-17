"use strict";
/**
 * extension.ts — Smart Proxy: Universal Interceptor + Context Router
 * ═══════════════════════════════════════════════════════════════════
 *
 * Architecture:
 *   Zero custom tools.  Copilot uses ALL native tools unimpeded.
 *   We sit invisibly in the agent loop:
 *     1. Let the LLM pick any tool it wants.
 *     2. Execute it natively via vscode.lm.invokeTool.
 *     3. Force-stringify the output (anti-object-injection).
 *     4. Extract the file extension from the tool input (if available).
 *     5. Pipe through smartSanitize(text, ext) — the Polyglot AST Router.
 *     6. Hand the sanitized string back to the LLM.
 *
 *   The Write-Guard intercepts write + terminal tools and emits a
 *   Markdown warning if the payload contains [MASKED_BY_SAFECHAT],
 *   preventing disk/system corruption from masked tokens.
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
exports.activate = activate;
const vscode = __importStar(require("vscode"));
const yaml = __importStar(require("yaml"));
const sanitizer_1 = require("./sanitizer");
// ────────────────────────────────────────────────────────────────────────────
// Write-Guard: tool name + description matching
// ────────────────────────────────────────────────────────────────────────────
/**
 * Hardcoded list of native tools that mutate files or execute commands.
 * Both file-write AND terminal tools are included — masked tokens in
 * either pathway can cause disk corruption or shell injection.
 */
const WRITE_TOOL_PATTERNS = [
    // File writes
    /^vscode_applyWorkspaceEdit$/i,
    /^apply_workspace_edit$/i,
    /^apply_edit$/i,
    /^edit_file$/i,
    /^write_file$/i,
    /^create_file$/i,
    /^insert_edit/i,
    /^replace_string/i,
    /^apply_diff/i,
    /^save_file$/i,
    /^overwrite_file$/i,
    // Terminal execution
    /^run_command$/i,
    /^terminal_execute$/i,
    /^run_in_terminal$/i,
    /^vscode_runCommand$/i,
    /^exec$/i,
    /^execute_command$/i,
    /^bash$/i,
];
const WRITE_DESC_KEYWORDS = [
    'apply workspace edit',
    'write to file',
    'create a file',
    'insert into file',
    'replace in file',
    'apply changes',
    'save file',
    'make a code change',
    'run a command',
    'execute command',
    'terminal',
    'shell command',
];
function isNativeWriteTool(name, description) {
    if (WRITE_TOOL_PATTERNS.some(p => p.test(name))) {
        return true;
    }
    const descLower = description.toLowerCase();
    return WRITE_DESC_KEYWORDS.some(kw => descLower.includes(kw));
}
// ────────────────────────────────────────────────────────────────────────────
// File Extension Extractor
// ────────────────────────────────────────────────────────────────────────────
/**
 * Attempts to extract a file extension from the tool's input object.
 * Looks for common property names that carry file paths:
 *   uri, filePath, path, file, fileName, resource
 * Returns the extension (e.g. '.json') or undefined for non-file tools.
 */
function extractFileExtension(input) {
    if (!input || typeof input !== 'object') {
        return undefined;
    }
    const record = input;
    // Check common keys that carry file paths
    const pathKeys = ['uri', 'filePath', 'path', 'file', 'fileName', 'resource', 'fsPath'];
    for (const key of pathKeys) {
        const val = record[key];
        if (typeof val === 'string' && val.length > 0) {
            return extractExtFromPath(val);
        }
    }
    // deep scan: look for nested objects with these keys
    for (const val of Object.values(record)) {
        if (val && typeof val === 'object' && !Array.isArray(val)) {
            const nested = val;
            for (const key of pathKeys) {
                const nv = nested[key];
                if (typeof nv === 'string' && nv.length > 0) {
                    return extractExtFromPath(nv);
                }
            }
        }
    }
    return undefined;
}
function extractExtFromPath(pathStr) {
    // Handle compound extensions like .env.local, .env.production
    const basename = pathStr.split(/[/\\]/).pop() ?? '';
    if (/^\.env\./i.test(basename)) {
        return basename.toLowerCase(); // e.g. ".env.local"
    }
    const dotIdx = basename.lastIndexOf('.');
    if (dotIdx > 0) {
        return basename.slice(dotIdx).toLowerCase();
    }
    // No extension — check if it's a dotfile like .env
    if (basename.startsWith('.') && basename.length > 1) {
        return basename.toLowerCase(); // e.g. ".env"
    }
    return undefined;
}
// ────────────────────────────────────────────────────────────────────────────
// Tool Output → String Extraction (anti-object-injection)
// ────────────────────────────────────────────────────────────────────────────
/**
 * Force-stringifies every part of a LanguageModelToolResult.
 * PromptTsxPart objects are JSON.stringify'd to prevent object-injection
 * bypasses where a crafted object could evade string-based regex scanning.
 */
function extractToolOutputAsString(res) {
    const parts = [];
    for (const part of res.content) {
        if (part instanceof vscode.LanguageModelTextPart) {
            parts.push(part.value);
        }
        else if (part instanceof vscode.LanguageModelPromptTsxPart) {
            try {
                parts.push(JSON.stringify(part.value, null, 2));
            }
            catch {
                parts.push(String(part.value));
            }
        }
        else {
            // Unknown part type — force string coercion
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
        (0, sanitizer_1.updateConfig)(null); // safely fallback
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Extension Activation
// ────────────────────────────────────────────────────────────────────────────
function activate(context) {
    const participant = vscode.chat.createChatParticipant('safecopilot.safeChat', chatRequestHandler);
    participant.iconPath = new vscode.ThemeIcon('shield');
    context.subscriptions.push(participant);
    console.log('[SafeChat] Smart Proxy activated — Polyglot AST Router online');
    // Load safechat.yml config on startup
    loadWorkspaceConfig();
    // Watch for safechat.yml file modifications in workspace
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
// The Universal Interceptor (chat request handler)
// ────────────────────────────────────────────────────────────────────────────
async function chatRequestHandler(request, chatContext, stream, token) {
    const messages = [];
    // ── Replay previous conversation turns ────────────────────────────────
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
    // ── Current user message ──────────────────────────────────────────────
    messages.push(vscode.LanguageModelChatMessage.User(request.prompt));
    const model = request.model;
    // ── Expose ALL native tools — no blocking, no custom tools ────────────
    const allTools = vscode.lm.tools.map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
    }));
    const requestOptions = allTools.length > 0
        ? { tools: allTools, toolMode: vscode.LanguageModelChatToolMode.Auto }
        : {};
    const MAX_TOOL_ROUNDS = 15;
    // ── Agentic Loop ──────────────────────────────────────────────────────
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
        // No tool calls — LLM is done, exit the loop
        if (toolCalls.length === 0) {
            break;
        }
        // Record the assistant's response in message history
        const assistantParts = [];
        if (assistantText) {
            assistantParts.push(new vscode.LanguageModelTextPart(assistantText));
        }
        assistantParts.push(...toolCalls);
        messages.push(vscode.LanguageModelChatMessage.Assistant(assistantParts));
        // ── Execute & Quarantine Loop ─────────────────────────────────────
        const toolResultParts = [];
        for (const call of toolCalls) {
            stream.progress(`Running tool: ${call.name}…`);
            console.log('[SafeChat] Tool call:', call.name);
            const toolDesc = vscode.lm.tools.find(t => t.name === call.name)?.description ?? '';
            // ── Write-Guard ─────────────────────────────────────────────────
            // Check BEFORE execution: if a write/terminal tool's input contains
            // masked tokens, warn the developer in the chat stream.
            if (isNativeWriteTool(call.name, toolDesc)) {
                const inputStr = JSON.stringify(call.input ?? {});
                if (inputStr.includes(sanitizer_1.MASK)) {
                    stream.markdown(`\n> ⚠️ **SafeChat Write-Guard**: Tool \`${call.name}\` was invoked ` +
                        `with input containing \`${sanitizer_1.MASK}\`. This could corrupt files or ` +
                        `execute masked credentials in the terminal. Please review the ` +
                        `operation carefully.\n\n`);
                }
            }
            // ── Native Execution ────────────────────────────────────────────
            let rawOutput = '';
            try {
                const result = await vscode.lm.invokeTool(call.name, { input: call.input, toolInvocationToken: request.toolInvocationToken }, token);
                // Force stringify — anti-object-injection quarantine
                rawOutput = extractToolOutputAsString(result);
            }
            catch (err) {
                rawOutput = `Error invoking tool ${call.name}: ${err instanceof Error ? err.message : String(err)}`;
            }
            // ── Context Router: extract extension → smartSanitize ──────────
            const ext = extractFileExtension(call.input);
            const { cleanText, wasModified, route } = (0, sanitizer_1.smartSanitize)(rawOutput, ext);
            if (wasModified) {
                stream.markdown(`\n🛡️ **SafeChat Proxy** (\`${route}\`): Scrubbed sensitive data ` +
                    `from \`${call.name}\` output.\n\n`);
            }
            // ── Hand sanitized result back to the LLM ─────────────────────
            toolResultParts.push(new vscode.LanguageModelToolResultPart(call.callId, [new vscode.LanguageModelTextPart(cleanText)]));
        }
        messages.push(vscode.LanguageModelChatMessage.User(toolResultParts));
    }
}
//# sourceMappingURL=extension.js.map