import * as vscode from 'vscode';
import { sanitizeAndCache, viewDiffCommand, readRulesConfig } from './sanitizer';

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

  // Load filter config once — used to decide which files to include
  const filterConfig = await readRulesConfig();
  const includeExts    = filterConfig?.includeExtensions;  // e.g. [".yaml", ".json", ".env"]
  const ignoreFiles    = filterConfig?.ignoreFiles;         // e.g. ["config/local.yaml"]
  const ignoreFolders  = filterConfig?.ignoreFolders;       // e.g. ["secrets", "infra/tfvars"]

  for (const ref of request.references) {
    const refValue = ref.value;

    // Resolve the URI regardless of whether it's a Uri or Location reference
    let baseUri: vscode.Uri | undefined;
    if (refValue instanceof vscode.Uri) {
      baseUri = refValue;
    } else if (refValue instanceof vscode.Location) {
      baseUri = refValue.uri;
    }
    if (!baseUri) { continue; }

    // Expand directories → flat list of file URIs (silently skips unreadable entries)
    const fileUris = await collectFiles(baseUri);

    for (const fileUri of fileUris) {
      const relPath = vscode.workspace.asRelativePath(fileUri, false);
      const normalizedRel = relPath.replace(/\\/g, '/');

      // ── Folder ignore list check ────────────────────────────────────
      if (ignoreFolders && ignoreFolders.length > 0) {
        const inIgnoredFolder = ignoreFolders.some(
          folder => normalizedRel === folder || normalizedRel.startsWith(folder + '/')
        );
        if (inIgnoredFolder) {
          stream.markdown(`> ℹ️ Skipped \`${relPath}\` (inside ignored folder)\n\n`);
          continue;
        }
      }

      // ── File ignore list check ──────────────────────────────────────
      if (ignoreFiles && ignoreFiles.length > 0) {
        if (ignoreFiles.includes(normalizedRel)) {
          stream.markdown(`> ℹ️ Skipped \`${relPath}\` (in ignore list)\n\n`);
          continue;
        }
      }

      // ── Extension allowlist check ───────────────────────────────────
      if (includeExts && includeExts.length > 0) {
        const ext = getFileExtension(fileUri);
        const allowed = includeExts.some(e => {
          const norm = (e.startsWith('.') ? e : '.' + e).toLowerCase();
          return ext === norm;
        });
        if (!allowed) {
          const extLabel = ext || '(no extension)';
          stream.markdown(
            `> ℹ️ Skipped \`${relPath}\` — extension \`${extLabel}\` is not in the ` +
            `\`include_extensions\` allowlist. Add it to \`.vscode/safechat-rules.yaml\` to enable sanitization.\n\n`
          );
          continue;
        }
      }

      // ── Read the file ─────────────────────────────────────────────
      try {
        const fileBytes = await vscode.workspace.fs.readFile(fileUri);
        rawContext += Buffer.from(fileBytes).toString('utf-8') + '\n';
      } catch (err) {
        stream.markdown(
          `> ⚠️ Could not read \`${relPath}\`: ${err}\n\n`
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

// ─────────────────────────────────────────────────────────────────────────────
// File-filtering helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Stats a URI and returns a flat list of all file URIs beneath it.
 * - If the URI is a plain file, returns [uri].
 * - If the URI is a directory, recursively enumerates all files inside it.
 * - Symlinks and unreadable entries are silently skipped.
 */
async function collectFiles(uri: vscode.Uri): Promise<vscode.Uri[]> {
  let stat: vscode.FileStat;
  try {
    stat = await vscode.workspace.fs.stat(uri);
  } catch {
    return []; // unreadable / broken symlink
  }

  if (stat.type === vscode.FileType.File) {
    return [uri];
  }

  if (stat.type === vscode.FileType.Directory) {
    let entries: [string, vscode.FileType][];
    try {
      entries = await vscode.workspace.fs.readDirectory(uri);
    } catch {
      return [];
    }
    const results: vscode.Uri[] = [];
    for (const [name, type] of entries) {
      if (type === vscode.FileType.File || type === vscode.FileType.Directory) {
        results.push(...await collectFiles(vscode.Uri.joinPath(uri, name)));
      }
    }
    return results;
  }

  return []; // symlinks, unknown types
}

/**
 * Returns the file extension from a URI path, lower-cased.
 * Dotfiles without a second dot (e.g. ".env") return their full basename (".env").
 * Files with no extension return an empty string.
 */
function getFileExtension(uri: vscode.Uri): string {
  const basename = uri.path.split('/').pop() ?? '';
  // Dotfiles like ".env", ".gitignore" — no second extension separator
  if (basename.startsWith('.') && !basename.slice(1).includes('.')) {
    return basename.toLowerCase(); // e.g. ".env"
  }
  const lastDot = basename.lastIndexOf('.');
  if (lastDot <= 0) { return ''; }
  return basename.slice(lastDot).toLowerCase(); // e.g. ".yaml"
}
