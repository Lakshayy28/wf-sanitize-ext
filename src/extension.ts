import * as vscode from 'vscode';
import { regexSanitize, MASK } from './sanitizer';

// ── The Write-Guard ────────────────────────────────────────────────────────

const NATIVE_WRITE_PATTERNS: RegExp[] = [
  /^apply_workspace_edit$/i,
  /^apply_edit$/i,
  /^create_file$/i,
  /^insert_edit/i,
  /^replace_string/i,
  /^apply_diff/i,
  /^save_file$/i,
  /^overwrite_file$/i,
];

const WRITE_DESC_KEYWORDS = [
  'apply workspace edit',
  'write to file',
  'create a file',
  'insert into file',
  'replace in file',
  'apply changes to file',
  'save file',
  'make a code change',
];

function isNativeWriteTool(name: string, description: string): boolean {
  if (NATIVE_WRITE_PATTERNS.some(p => p.test(name))) { return true; }
  const descLower = description.toLowerCase();
  return WRITE_DESC_KEYWORDS.some(kw => descLower.includes(kw));
}

// ── Extension Activation ────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  const participant = vscode.chat.createChatParticipant(
    'safecopilot.safeChat',
    chatRequestHandler,
  );
  participant.iconPath = new vscode.ThemeIcon('shield');

  context.subscriptions.push(participant);
}

// ── Extraction Helper ───────────────────────────────────────────────────────

function extractToolParts(res: vscode.LanguageModelToolResult): string {
    let combined = '';
    for (const part of res.content) {
        if (part instanceof vscode.LanguageModelTextPart) {
            combined += part.value + '\n';
        } else if (part instanceof vscode.LanguageModelPromptTsxPart) {
            try {
                combined += JSON.stringify(part.value, null, 2) + '\n';
            } catch {
                combined += String(part.value) + '\n';
            }
        }
    }
    return combined;
}

// ── The Universal Interceptor ───────────────────────────────────────────────

async function chatRequestHandler(
  request: vscode.ChatRequest,
  chatContext: vscode.ChatContext,
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
): Promise<void> {
  const messages: vscode.LanguageModelChatMessage[] = [];

  // Replay previous conversation turns
  for (const turn of chatContext.history) {
    if (turn instanceof vscode.ChatRequestTurn) {
      if (turn.participant === 'safecopilot.safeChat') {
        messages.push(vscode.LanguageModelChatMessage.User(turn.prompt));
      }
    } else if (turn instanceof vscode.ChatResponseTurn) {
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
  
  // Expose all native tools directly back to the LLM agent unimpeded
  const allTools = vscode.lm.tools.map(t => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema
  }));

  const requestOptions: vscode.LanguageModelChatRequestOptions = allTools.length > 0
    ? { tools: allTools, toolMode: vscode.LanguageModelChatToolMode.Auto }
    : {};

  const MAX_TOOL_ROUNDS = 15;

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const chatResponse = await model.sendRequest(messages, requestOptions, token);
    const toolCalls: vscode.LanguageModelToolCallPart[] = [];
    let assistantText = '';

    for await (const chunk of chatResponse.stream) {
      if (chunk instanceof vscode.LanguageModelTextPart) {
        stream.markdown(chunk.value);
        assistantText += chunk.value;
      } else if (chunk instanceof vscode.LanguageModelToolCallPart) {
        toolCalls.push(chunk);
      }
    }

    // No tools called, the LLM has generated a final response
    if (toolCalls.length === 0) {
      break;
    }

    const assistantParts: (vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart)[] = [];
    if (assistantText) {
      assistantParts.push(new vscode.LanguageModelTextPart(assistantText));
    }
    assistantParts.push(...toolCalls);
    messages.push(vscode.LanguageModelChatMessage.Assistant(assistantParts));

    const toolResultParts: vscode.LanguageModelToolResultPart[] = [];

    // The execute & quarantine loop
    for (const call of toolCalls) {
      stream.progress(`Running tool natively: ${call.name}…`);
      
      const toolDesc = vscode.lm.tools.find(t => t.name === call.name)?.description ?? '';

      // Check the write-guard before allowing standard execution
      if (isNativeWriteTool(call.name, toolDesc)) {
          const inputString = JSON.stringify(call.input ?? {});
          if (inputString.includes(MASK)) {
              stream.markdown(`\n> ⚠️ **SafeChat Warning**: A write tool (\`${call.name}\`) was initiated containing masked credentials (\`${MASK}\`).\n> Proceeding with execution natively, but please review the diffs locally. To preserve safety, View Masked Diff functionality has been removed.\n\n`);
          }
      }

      let rawOutputStr = '';
      try {
          // Native execution path
          const result = await vscode.lm.invokeTool(
              call.name, 
              { input: call.input, toolInvocationToken: request.toolInvocationToken }, 
              token
          );
          // Quarantine into string
          rawOutputStr = extractToolParts(result);
      } catch (err) {
          rawOutputStr = `Error invoking tool ${call.name}: ${err instanceof Error ? err.message : String(err)}`;
      }

      // Proxy scan
      const { cleanText, wasModified } = regexSanitize(rawOutputStr);

      if (wasModified) {
          stream.markdown(`\n🛡️ **SafeChat Proxy:** Intercepted and scrubbed sensitive data from \`${call.name}\` output entirely via Regex.\n\n`);
      }

      // Hand back to language model context
      const safeResultPart = new vscode.LanguageModelToolResultPart(call.callId, [new vscode.LanguageModelTextPart(cleanText)]);
      toolResultParts.push(safeResultPart);
    }
    
    messages.push(vscode.LanguageModelChatMessage.User(toolResultParts));
  }
}
