import * as vscode from 'vscode';
import { sanitizeAndCache, viewDiffCommand } from './sanitizer';

// Module-level reference so the chat handler can access the extension path.
let extensionPath: string;

export function activate(context: vscode.ExtensionContext) {
  extensionPath = context.extensionPath;

  // ── Register the @safechat Chat Participant ──────────────────────────
  const participant = vscode.chat.createChatParticipant(
    'safecopilot.safeChat',
    chatRequestHandler
  );
  participant.iconPath = new vscode.ThemeIcon('shield');

  // ── Register the "View Masked Diff" command ──────────────────────────
  const diffCommand = vscode.commands.registerCommand(
    'safecopilot.viewDiff',
    viewDiffCommand
  );

  context.subscriptions.push(participant, diffCommand);
}

/**
 * The core Chat Request Handler.
 * 1. Extracts file references from the user's prompt.
 * 2. Delegates to the sanitizer.
 * 3. Forwards the clean payload to the Copilot Language Model.
 */
async function chatRequestHandler(
  request: vscode.ChatRequest,
  _chatContext: vscode.ChatContext,
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken
): Promise<void> {
  // ── Step 1: Extract raw context from attached references ─────────────
  stream.progress('Scanning attached context for sensitive data…');

  let rawContext = '';

  for (const ref of request.references) {
    const refValue = ref.value;
    if (refValue instanceof vscode.Uri) {
      try {
        const fileBytes = await vscode.workspace.fs.readFile(refValue);
        rawContext += Buffer.from(fileBytes).toString('utf-8') + '\n';
      } catch (err) {
        stream.markdown(
          `> ⚠️ Could not read reference \`${refValue.fsPath}\`: ${err}\n\n`
        );
      }
    } else if (refValue instanceof vscode.Location) {
      try {
        const fileBytes = await vscode.workspace.fs.readFile(refValue.uri);
        rawContext += Buffer.from(fileBytes).toString('utf-8') + '\n';
      } catch (err) {
        stream.markdown(
          `> ⚠️ Could not read location reference \`${refValue.uri.fsPath}\`: ${err}\n\n`
        );
      }
    }
  }

  // ── Step 2: Sanitize the context ─────────────────────────────────────
  const { cleanText, wasModified, cacheEntryUri, presidioError } =
    await sanitizeAndCache(rawContext, extensionPath);

  if (presidioError) {
    stream.markdown(
      `> ⚠️ **Advanced PII detection unavailable** (Presidio server unreachable). ` +
      `Falling back to regex-only masking.\n` +
      `> Start the server: \`uvicorn presidio_server.main:app --port 8000\`\n\n`
    );
  }

  if (wasModified) {
    stream.markdown(
      '🛡️ **Sensitive data was detected and masked** before sending to Copilot.\n\n'
    );
    stream.button({
      command: 'safecopilot.viewDiff',
      title: '$(diff) View Masked Diff',
      // Pass this prompt's specific cache URI as an argument so the button
      // always opens its own diff, even after subsequent prompts have run.
      arguments: cacheEntryUri ? [cacheEntryUri.toString()] : [],
    });
  }

  // ── Step 3: Select a Copilot Language Model ──────────────────────────
  stream.progress('Sending sanitized context to Copilot…');

  let model: vscode.LanguageModelChat | undefined;
  try {
    const models = await vscode.lm.selectChatModels({
      vendor: 'copilot',
      family: 'gpt-4o',
    });
    model = models?.[0];
  } catch {
    // Model selection failed — fall through to the guard below.
  }

  if (!model) {
    stream.markdown(
      '> ⚠️ No Copilot language model found. Make sure GitHub Copilot Chat is installed and signed in.\n'
    );
    return;
  }

  // ── Step 4: Build messages and stream the response ───────────────────
  const systemMessage = vscode.LanguageModelChatMessage.User(
    'You are a helpful coding assistant. The following context has been pre-sanitized to remove sensitive information. ' +
      'Treat any `[MASKED_BY_SAFECHAT]` or `<ENTITY_TYPE>` placeholders as redacted secrets — do not attempt to guess their values.'
  );

  const combinedPrompt =
    cleanText.length > 0
      ? `Context:\n\`\`\`\n${cleanText}\n\`\`\`\n\nUser question: ${request.prompt}`
      : request.prompt;

  const userMessage = vscode.LanguageModelChatMessage.User(combinedPrompt);

  try {
    const chatResponse = await model.sendRequest(
      [systemMessage, userMessage],
      {},
      token
    );

    for await (const fragment of chatResponse.text) {
      stream.markdown(fragment);
    }
  } catch (err) {
    if (err instanceof vscode.LanguageModelError) {
      const lmErr = err as vscode.LanguageModelError;
      stream.markdown(
        `> ⚠️ Language model error (${lmErr.code ?? 'unknown'}): ${lmErr.message}\n`
      );
    } else {
      throw err;
    }
  }
}

export function deactivate() {
  // Nothing to clean up.
}
