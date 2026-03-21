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
// Module-level reference so the chat handler can access the extension path.
let extensionPath;
function activate(context) {
    extensionPath = context.extensionPath;
    // ── Register the @safechat Chat Participant ──────────────────────────
    const participant = vscode.chat.createChatParticipant('safecopilot.safeChat', chatRequestHandler);
    participant.iconPath = new vscode.ThemeIcon('shield');
    // ── Register the "View Masked Diff" command ──────────────────────────
    const diffCommand = vscode.commands.registerCommand('safecopilot.viewDiff', sanitizer_1.viewDiffCommand);
    context.subscriptions.push(participant, diffCommand);
}
/**
 * The core Chat Request Handler.
 * 1. Extracts file references from the user's prompt.
 * 2. Delegates to the sanitizer.
 * 3. Forwards the clean payload to the Copilot Language Model.
 */
async function chatRequestHandler(request, _chatContext, stream, token) {
    // ── Step 1: Extract raw context from attached references ─────────────
    stream.progress('Scanning attached context for sensitive data…');
    let rawContext = '';
    for (const ref of request.references) {
        const refValue = ref.value;
        if (refValue instanceof vscode.Uri) {
            try {
                const fileBytes = await vscode.workspace.fs.readFile(refValue);
                rawContext += Buffer.from(fileBytes).toString('utf-8') + '\n';
            }
            catch (err) {
                stream.markdown(`> ⚠️ Could not read reference \`${refValue.fsPath}\`: ${err}\n\n`);
            }
        }
        else if (refValue instanceof vscode.Location) {
            try {
                const fileBytes = await vscode.workspace.fs.readFile(refValue.uri);
                rawContext += Buffer.from(fileBytes).toString('utf-8') + '\n';
            }
            catch (err) {
                stream.markdown(`> ⚠️ Could not read location reference \`${refValue.uri.fsPath}\`: ${err}\n\n`);
            }
        }
    }
    // ── Step 2: Sanitize the context ─────────────────────────────────────
    const { cleanText, wasModified } = await (0, sanitizer_1.sanitizeAndCache)(rawContext, extensionPath);
    if (wasModified) {
        stream.markdown('🛡️ **Sensitive data was detected and masked** before sending to Copilot.\n\n');
        stream.button({
            command: 'safecopilot.viewDiff',
            title: '$(diff) View Masked Diff',
        });
    }
    // ── Step 3: Select a Copilot Language Model ──────────────────────────
    stream.progress('Sending sanitized context to Copilot…');
    let model;
    try {
        const models = await vscode.lm.selectChatModels({
            vendor: 'copilot',
            family: 'gpt-4o',
        });
        model = models?.[0];
    }
    catch {
        // Model selection failed — fall through to the guard below.
    }
    if (!model) {
        stream.markdown('> ⚠️ No Copilot language model found. Make sure GitHub Copilot Chat is installed and signed in.\n');
        return;
    }
    // ── Step 4: Build messages and stream the response ───────────────────
    const systemMessage = vscode.LanguageModelChatMessage.User('You are a helpful coding assistant. The following context has been pre-sanitized to remove sensitive information. ' +
        'Treat any `[MASKED_BY_SAFECHAT]` or `<ENTITY_TYPE>` placeholders as redacted secrets — do not attempt to guess their values.');
    const combinedPrompt = cleanText.length > 0
        ? `Context:\n\`\`\`\n${cleanText}\n\`\`\`\n\nUser question: ${request.prompt}`
        : request.prompt;
    const userMessage = vscode.LanguageModelChatMessage.User(combinedPrompt);
    try {
        const chatResponse = await model.sendRequest([systemMessage, userMessage], {}, token);
        for await (const fragment of chatResponse.text) {
            stream.markdown(fragment);
        }
    }
    catch (err) {
        if (err instanceof vscode.LanguageModelError) {
            const lmErr = err;
            stream.markdown(`> ⚠️ Language model error (${lmErr.code ?? 'unknown'}): ${lmErr.message}\n`);
        }
        else {
            throw err;
        }
    }
}
function deactivate() {
    // Nothing to clean up.
}
//# sourceMappingURL=extension.js.map