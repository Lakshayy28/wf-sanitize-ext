import * as vscode from 'vscode';
import { sanitizeOnly, readRulesConfig, RulesConfig } from './sanitizer';

let extensionPath: string;

// ── Per-file state tracking (persists across requests in the session) ───────

interface FileState {
  relPath: string;
  mtime: number;
  isSensitive: boolean;
  originalContent: string;
  sanitizedContent: string;
  wasMasked: boolean;
}

/** Efficiency cache — keyed by URI string, survives across conversations. */
const fileStateCache = new Map<string, FileState>();

/** Files referenced in the current conversation — cleared on new chat. */
let conversationFileKeys = new Set<string>();

/** Latest per-file diff cache directory for command-palette fallback. */
let latestCacheEntryUri: vscode.Uri | undefined;

// ── Activation ──────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  extensionPath = context.extensionPath;

  const participant = vscode.chat.createChatParticipant(
    'safecopilot.safeChat',
    chatRequestHandler,
  );
  participant.iconPath = new vscode.ThemeIcon('shield');

  const diffCmd = vscode.commands.registerCommand(
    'safecopilot.viewDiff',
    handleViewDiff,
  );

  context.subscriptions.push(participant, diffCmd);
}

// ── Chat Request Handler ────────────────────────────────────────────────────

async function chatRequestHandler(
  request: vscode.ChatRequest,
  chatContext: vscode.ChatContext,
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
): Promise<void> {
  // New conversation → clear the conversation-scoped file set.
  if (chatContext.history.length === 0) {
    conversationFileKeys.clear();
  }

  stream.progress('Scanning attached context for sensitive data…');

  const filterConfig = await readRulesConfig();
  const includeExts = filterConfig?.includeExtensions;

  // ── Step 1: Resolve file URIs from all attached references ───────────
  const referencedUris = await resolveAllReferences(request.references);

  // ── Step 2: Process each file — reuse cache or (re-)sanitize ─────────
  let newMasks = 0;
  let anyPresidioError: string | undefined;

  for (const fileUri of referencedUris) {
    const key = fileUri.toString();
    conversationFileKeys.add(key);

    let stat: vscode.FileStat;
    try {
      stat = await vscode.workspace.fs.stat(fileUri);
    } catch { continue; }
    if (stat.type !== vscode.FileType.File) { continue; }

    // Unchanged since last scan → reuse cached result
    const cached = fileStateCache.get(key);
    if (cached && cached.mtime === stat.mtime) { continue; }

    const relPath = vscode.workspace.asRelativePath(fileUri, false);
    let text: string;
    try {
      const bytes = await vscode.workspace.fs.readFile(fileUri);
      text = Buffer.from(bytes).toString('utf-8');
    } catch { continue; }

    // Should this file type be sanitized?
    let isSensitive: boolean;
    if (includeExts && includeExts.length > 0) {
      const ext = getFileExtension(fileUri);
      isSensitive = includeExts.some(e => {
        const norm = (e.startsWith('.') ? e : '.' + e).toLowerCase();
        return ext === norm;
      });
    } else {
      isSensitive = true; // no filter → scan everything
    }

    if (isSensitive) {
      const result = await sanitizeOnly(text, filterConfig);
      if (result.presidioError) { anyPresidioError = result.presidioError; }
      fileStateCache.set(key, {
        relPath, mtime: stat.mtime, isSensitive: true,
        originalContent: text, sanitizedContent: result.cleanText,
        wasMasked: result.wasModified,
      });
      if (result.wasModified) { newMasks++; }
    } else {
      fileStateCache.set(key, {
        relPath, mtime: stat.mtime, isSensitive: false,
        originalContent: text, sanitizedContent: text,
        wasMasked: false,
      });
    }
  }

  // ── Step 3: Build context from ALL files in the conversation ─────────
  const contextParts: string[] = [];
  const maskedFiles: { relPath: string; original: string; masked: string }[] = [];

  for (const key of conversationFileKeys) {
    const state = fileStateCache.get(key);
    if (!state) { continue; }
    contextParts.push(`// File: ${state.relPath}\n${state.sanitizedContent}`);
    if (state.wasMasked) {
      maskedFiles.push({
        relPath: state.relPath,
        original: state.originalContent,
        masked: state.sanitizedContent,
      });
    }
  }

  // ── Step 4: Write per-file diff cache (only when new masks appeared) ─
  if (newMasks > 0 && maskedFiles.length > 0) {
    await writePerFileDiffCache(maskedFiles);
  }

  // ── Notifications ────────────────────────────────────────────────────
  if (anyPresidioError) {
    stream.markdown(
      '> ⚠️ **Advanced PII detection unavailable** (Presidio server unreachable). ' +
      'Falling back to regex-only masking.\n' +
      '> Start the server: `uvicorn presidio_server.main:app --port 8000`\n\n',
    );
  }

  if (maskedFiles.length > 0) {
    stream.markdown(
      `🛡️ **${maskedFiles.length} file(s) contain masked sensitive data.**\n\n`,
    );
    stream.button({
      command: 'safecopilot.viewDiff',
      title: '$(diff) View Masked Diff',
      arguments: latestCacheEntryUri ? [latestCacheEntryUri.toString()] : [],
    });
  }

  // ── Step 5: Select a Copilot Language Model ──────────────────────────
  stream.progress('Sending sanitized context to Copilot…');

  let model: vscode.LanguageModelChat | undefined;
  try {
    const models = await vscode.lm.selectChatModels({
      vendor: 'copilot',
      family: 'gpt-4o',
    });
    model = models?.[0];
  } catch { /* fall through */ }

  if (!model) {
    stream.markdown(
      '> ⚠️ No Copilot language model found. Make sure GitHub Copilot Chat is installed and signed in.\n',
    );
    return;
  }

  // ── Step 6: Build messages with conversation history ─────────────────
  const messages: vscode.LanguageModelChatMessage[] = [];

  // System prompt
  messages.push(vscode.LanguageModelChatMessage.User(
    'You are a helpful coding assistant. Some of the provided file context has been ' +
    'pre-sanitized to remove sensitive information. Treat any `[MASKED_BY_SAFECHAT]` ' +
    'or `<ENTITY_TYPE>` placeholders as redacted secrets — do not attempt to guess ' +
    'their original values. Other files are provided as-is without modification. ' +
    'Maintain full awareness of all provided context across the conversation.',
  ));

  // Replay previous conversation turns for multi-turn continuity
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

  // Current message — full accumulated context + user question
  const fullContext = contextParts.join('\n\n');
  const currentMessage = fullContext.length > 0
    ? `Context (${conversationFileKeys.size} file(s)):\n\`\`\`\n${fullContext}\n\`\`\`\n\nUser question: ${request.prompt}`
    : request.prompt;

  messages.push(vscode.LanguageModelChatMessage.User(currentMessage));

  // ── Step 7: Stream the LLM response ──────────────────────────────────
  try {
    const chatResponse = await model.sendRequest(messages, {}, token);
    for await (const fragment of chatResponse.text) {
      stream.markdown(fragment);
    }
  } catch (err) {
    if (err instanceof vscode.LanguageModelError) {
      stream.markdown(
        `> ⚠️ Language model error (${(err as vscode.LanguageModelError).code ?? 'unknown'}): ${err.message}\n`,
      );
    } else {
      throw err;
    }
  }
}

export function deactivate() {}

// ── Reference Resolution ────────────────────────────────────────────────────

async function resolveAllReferences(
  references: readonly vscode.ChatPromptReference[],
): Promise<vscode.Uri[]> {
  const uris: vscode.Uri[] = [];

  for (const ref of references) {
    const refId = (ref.id ?? '').toLowerCase();

    // #codebase / workspace-wide reference
    if (refId.includes('codebase') || refId.includes('workspace')) {
      const folders = vscode.workspace.workspaceFolders;
      if (folders) {
        for (const folder of folders) {
          uris.push(...await collectFiles(folder.uri));
        }
      }
      continue;
    }

    // Resolve value → URI
    const refValue = ref.value;
    let baseUri: vscode.Uri | undefined;

    if (refValue instanceof vscode.Uri) {
      baseUri = refValue;
    } else if (refValue instanceof vscode.Location) {
      baseUri = refValue.uri;
    } else if (typeof refValue === 'string' && refValue.length > 0) {
      const folders = vscode.workspace.workspaceFolders;
      if (folders?.length) {
        const candidate = vscode.Uri.joinPath(folders[0].uri, refValue);
        try {
          await vscode.workspace.fs.stat(candidate);
          baseUri = candidate;
        } catch { /* not a valid path */ }
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
        } catch { /* not a valid path */ }
      }
    }

    if (baseUri) {
      uris.push(...await collectFiles(baseUri));
    }
  }

  // Deduplicate by URI string
  const seen = new Set<string>();
  return uris.filter(u => {
    const key = u.toString();
    if (seen.has(key)) { return false; }
    seen.add(key);
    return true;
  });
}

// ── File Collection ─────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', '__pycache__', '.temp_cache',
  'out', 'dist', 'build', '.next', '.nuxt', 'coverage',
]);

async function collectFiles(uri: vscode.Uri): Promise<vscode.Uri[]> {
  let stat: vscode.FileStat;
  try {
    stat = await vscode.workspace.fs.stat(uri);
  } catch {
    return [];
  }

  if (stat.type === vscode.FileType.File) {
    return [uri];
  }

  if (stat.type === vscode.FileType.Directory) {
    const dirName = uri.path.split('/').pop() ?? '';
    if (SKIP_DIRS.has(dirName)) { return []; }

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

  return [];
}

function getFileExtension(uri: vscode.Uri): string {
  const basename = uri.path.split('/').pop() ?? '';
  if (basename.startsWith('.') && !basename.slice(1).includes('.')) {
    return basename.toLowerCase();
  }
  const lastDot = basename.lastIndexOf('.');
  if (lastDot <= 0) { return ''; }
  return basename.slice(lastDot).toLowerCase();
}

// ── Per-file Diff Cache ─────────────────────────────────────────────────────

function getCacheBaseUri(): vscode.Uri | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) { return undefined; }
  return vscode.Uri.joinPath(folders[0].uri, '.vscode', '.temp_cache');
}

function timestampSlug(): string {
  const now = new Date();
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return (
    `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
    `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}` +
    `-${pad(now.getMilliseconds(), 3)}`
  );
}

async function writePerFileDiffCache(
  maskedFiles: { relPath: string; original: string; masked: string }[],
): Promise<void> {
  const baseUri = getCacheBaseUri();
  if (!baseUri) { return; }

  await vscode.workspace.fs.createDirectory(baseUri);

  // Ensure .gitignore exists
  const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
  try { await vscode.workspace.fs.stat(gitignoreUri); }
  catch { await vscode.workspace.fs.writeFile(gitignoreUri, Buffer.from('*\n', 'utf-8')); }

  const entryDir = vscode.Uri.joinPath(baseUri, timestampSlug());
  await vscode.workspace.fs.createDirectory(entryDir);

  // Write per-file original + masked pairs
  for (const file of maskedFiles) {
    const safeName = file.relPath.replace(/[/\\]/g, '_');
    await Promise.all([
      vscode.workspace.fs.writeFile(
        vscode.Uri.joinPath(entryDir, `${safeName}.original.txt`),
        Buffer.from(file.original, 'utf-8'),
      ),
      vscode.workspace.fs.writeFile(
        vscode.Uri.joinPath(entryDir, `${safeName}.masked.txt`),
        Buffer.from(file.masked, 'utf-8'),
      ),
    ]);
  }

  // Manifest listing all masked file paths
  await vscode.workspace.fs.writeFile(
    vscode.Uri.joinPath(entryDir, 'manifest.json'),
    Buffer.from(JSON.stringify(maskedFiles.map(f => f.relPath)), 'utf-8'),
  );

  latestCacheEntryUri = entryDir;
}

// ── Diff Viewer (per-file with QuickPick) ───────────────────────────────────

async function handleViewDiff(entryUriString?: string): Promise<void> {
  let entryUri: vscode.Uri | undefined;

  if (entryUriString) {
    entryUri = vscode.Uri.parse(entryUriString);
  } else {
    entryUri = latestCacheEntryUri;
    if (!entryUri) {
      // Try to recover the most recent cache entry from disk
      const baseUri = getCacheBaseUri();
      if (baseUri) {
        try {
          const entries = await vscode.workspace.fs.readDirectory(baseUri);
          const dirs = entries
            .filter(([, type]) => type === vscode.FileType.Directory)
            .map(([name]) => name)
            .sort()
            .reverse();
          if (dirs.length > 0) {
            entryUri = vscode.Uri.joinPath(baseUri, dirs[0]);
          }
        } catch { /* no cache yet */ }
      }
    }
  }

  if (!entryUri) {
    vscode.window.showWarningMessage(
      'SafeChat: No cached diff available yet. Attach a file to @safechat first.',
    );
    return;
  }

  try {
    const manifestBytes = await vscode.workspace.fs.readFile(
      vscode.Uri.joinPath(entryUri, 'manifest.json'),
    );
    const files: string[] = JSON.parse(Buffer.from(manifestBytes).toString('utf-8'));
    if (files.length === 0) { return; }

    if (files.length === 1) {
      // Single file — open diff directly
      const safeName = files[0].replace(/[/\\]/g, '_');
      await vscode.commands.executeCommand(
        'vscode.diff',
        vscode.Uri.joinPath(entryUri, `${safeName}.original.txt`),
        vscode.Uri.joinPath(entryUri, `${safeName}.masked.txt`),
        `Original ↔ Sanitized: ${files[0]}`,
      );
      return;
    }

    // Multiple files — show QuickPick
    const picked = await vscode.window.showQuickPick(
      files.map(f => ({ label: f, description: 'View sanitization diff' })),
      { placeHolder: 'Select a file to view its sanitization diff' },
    );
    if (picked) {
      const safeName = picked.label.replace(/[/\\]/g, '_');
      await vscode.commands.executeCommand(
        'vscode.diff',
        vscode.Uri.joinPath(entryUri, `${safeName}.original.txt`),
        vscode.Uri.joinPath(entryUri, `${safeName}.masked.txt`),
        `Original ↔ Sanitized: ${picked.label}`,
      );
    }
  } catch {
    // Fall back to legacy single-pair format
    await vscode.commands.executeCommand(
      'vscode.diff',
      vscode.Uri.joinPath(entryUri, 'original_context.txt'),
      vscode.Uri.joinPath(entryUri, 'masked_context.txt'),
      `Original ↔ Sanitized [${entryUri.path.split('/').pop()}]`,
    );
  }
}
