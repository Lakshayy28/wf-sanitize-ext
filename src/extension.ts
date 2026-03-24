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
  rulesHash: string;
}

const fileStateCache = new Map<string, FileState>();
let conversationFileKeys = new Set<string>();
let latestCacheEntryUri: vscode.Uri | undefined;
let lastRulesHash: string | undefined;

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

  const filterConfig = await readRulesConfig();
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

  // ── Step 1: Resolve file URIs from all attached references ───────────
  const referencedUris = await resolveAllReferences(request.references, request.prompt);
  console.log('[SafeChat] resolvedUris count:', referencedUris.length);
  if (referencedUris.length > 0) {
    console.log('[SafeChat] first 5 URIs:', referencedUris.slice(0, 5).map(u => u.toString()));
  }

  // ── Step 2: Process each file — reuse cache or (re-)sanitize ─────────
  let newMasks = 0;
  let anyPresidioError: string | undefined;
  const staleKeys = new Set<string>();

  for (const fileUri of referencedUris) {
    const key = fileUri.toString();
    conversationFileKeys.add(key);

    let stat: vscode.FileStat;
    try {
      stat = await vscode.workspace.fs.stat(fileUri);
    } catch { staleKeys.add(key); continue; }
    if (stat.type !== vscode.FileType.File) { continue; }

    const cached = fileStateCache.get(key);
    if (cached && cached.mtime === stat.mtime && cached.rulesHash === rulesHash) { continue; }

    const relPath = vscode.workspace.asRelativePath(fileUri, false);
    let text: string;
    try {
      const bytes = await vscode.workspace.fs.readFile(fileUri);
      text = Buffer.from(bytes).toString('utf-8');
    } catch { continue; }

    let isSensitive: boolean;
    if (includeExts && includeExts.length > 0) {
      const ext = getFileExtension(fileUri);
      isSensitive = includeExts.some(e => {
        const norm = (e.startsWith('.') ? e : '.' + e).toLowerCase();
        return ext === norm;
      });
    } else {
      isSensitive = true;
    }

    if (isSensitive) {
      const result = await sanitizeOnly(text, filterConfig);
      if (result.presidioError) { anyPresidioError = result.presidioError; }
      fileStateCache.set(key, {
        relPath, mtime: stat.mtime, isSensitive: true,
        originalContent: text, sanitizedContent: result.cleanText,
        wasMasked: result.wasModified, rulesHash,
      });
      if (result.wasModified) { newMasks++; }
    } else {
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

  // ── Step 4: Write per-file diff cache ────────────────────────────────
  // Rewrite when new masks appear OR when disk cache was deleted/cleared
  if (maskedFiles.length > 0 && (newMasks > 0 || !diskExists)) {
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

  // ── Step 5: Use the user's selected model (same as Copilot uses) ─────
  stream.progress('Sending sanitized context to Copilot…');

  const model = request.model;

  // ── Step 6: Gather all available tools for full agentic behaviour ────
  const MAX_TOOLS = 128;

  // Prioritize tools the user explicitly attached
  const priorityNames = new Set(request.toolReferences.map(r => r.name));
  const allTools: vscode.LanguageModelChatTool[] = [];

  // Add priority (user-referenced) tools first — skip malformed schemas
  for (const t of vscode.lm.tools) {
    if (priorityNames.has(t.name) && isToolSchemaValid(t.inputSchema)) {
      allTools.push({ name: t.name, description: t.description, inputSchema: t.inputSchema });
    }
  }

  // Fill remaining slots — skip tools with invalid schemas
  // (e.g. MCP tools declaring type:"object" without "properties" cause 400 errors)
  for (const t of vscode.lm.tools) {
    if (allTools.length >= MAX_TOOLS) { break; }
    if (!priorityNames.has(t.name) && isToolSchemaValid(t.inputSchema)) {
      allTools.push({ name: t.name, description: t.description, inputSchema: t.inputSchema });
    }
  }

  // ── Step 7: Build messages with conversation history ─────────────────
  const messages: vscode.LanguageModelChatMessage[] = [];

  // System prompt
  messages.push(vscode.LanguageModelChatMessage.User(
    'You are a highly skilled coding assistant with full access to the workspace. ' +
    'You have tools available to search code, read files, list directories, run commands, and more. ' +
    'Use these tools proactively to gather context, explore the codebase, and provide thorough, detailed answers. ' +
    'Think step by step. When the user asks about code, search the codebase, read the relevant files, ' +
    'and provide comprehensive analysis.\n\n' +
    'IMPORTANT: Some of the provided file context has been pre-sanitized to protect sensitive data. ' +
    'Treat any `[MASKED_BY_SAFECHAT]` or `<ENTITY_TYPE>` placeholders as redacted secrets — ' +
    'do not attempt to guess their original values. ' +
    'Other files are provided as-is without modification.',
  ));

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

  // Current message — full accumulated context + user question
  const fullContext = contextParts.join('\n\n');
  const currentMessage = fullContext.length > 0
    ? `Context (${conversationFileKeys.size} file(s)):\n\`\`\`\n${fullContext}\n\`\`\`\n\nUser question: ${request.prompt}`
    : request.prompt;

  messages.push(vscode.LanguageModelChatMessage.User(currentMessage));

  // ── Step 8: Agentic tool-calling loop ────────────────────────────────
  const MAX_TOOL_ROUNDS = 15;

  const requestOptions: vscode.LanguageModelChatRequestOptions = allTools.length > 0
    ? { tools: allTools, toolMode: vscode.LanguageModelChatToolMode.Auto }
    : {};

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const chatResponse = await model.sendRequest(messages, requestOptions, token);

    // Collect tool calls and text from this round
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

    // No tool calls → model is done, exit the loop
    if (toolCalls.length === 0) {
      break;
    }

    // Record the assistant's response (text + tool calls) in the message history
    const assistantParts: (vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart)[] = [];
    if (assistantText) {
      assistantParts.push(new vscode.LanguageModelTextPart(assistantText));
    }
    assistantParts.push(...toolCalls);
    messages.push(vscode.LanguageModelChatMessage.Assistant(assistantParts));

    // Invoke each tool and collect results
    const toolResultParts: vscode.LanguageModelToolResultPart[] = [];

    for (const call of toolCalls) {
      stream.progress(`Running tool: ${call.name}…`);

      let resultContent: (vscode.LanguageModelTextPart | vscode.LanguageModelPromptTsxPart)[];
      try {
        const result = await vscode.lm.invokeTool(call.name, {
          input: call.input,
          toolInvocationToken: request.toolInvocationToken,
        }, token);

        resultContent = result.content as (vscode.LanguageModelTextPart | vscode.LanguageModelPromptTsxPart)[];
      } catch (err) {
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

export function deactivate() {}

// ── Cache Invalidation Helpers ──────────────────────────────────────────────

/** Simple 32-bit hash for fast cache-key comparisons (not cryptographic). */
function computeConfigHash(config: RulesConfig | undefined): string {
  const str = JSON.stringify(config ?? {});
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h) + str.charCodeAt(i);
    h |= 0;
  }
  return h.toString(36);
}

/** Returns true if the `.vscode/.temp_cache` folder exists on disk. */
async function diskCacheExists(): Promise<boolean> {
  const baseUri = getCacheBaseUri();
  if (!baseUri) { return false; }
  try {
    await vscode.workspace.fs.stat(baseUri);
    return true;
  } catch {
    return false;
  }
}

// ── Tool Schema Validation ──────────────────────────────────────────────────

/**
 * Returns false if the JSON Schema would cause the Copilot API to reject the
 * entire request (e.g. `{ type: "object" }` without `properties`).
 */
function isToolSchemaValid(schema: unknown): boolean {
  if (schema === undefined || schema === null) { return true; }
  return !hasObjectWithoutProperties(schema);
}

function hasObjectWithoutProperties(node: unknown): boolean {
  if (typeof node !== 'object' || node === null) { return false; }
  const s = node as Record<string, unknown>;
  if (s['type'] === 'object' && !('properties' in s)) { return true; }
  for (const val of Object.values(s)) {
    if (typeof val === 'object' && val !== null) {
      if (hasObjectWithoutProperties(val)) { return true; }
    }
  }
  return false;
}

// ── Reference Resolution ────────────────────────────────────────────────────

async function resolveAllReferences(
  references: readonly vscode.ChatPromptReference[],
  promptText?: string,
): Promise<vscode.Uri[]> {
  const uris: vscode.Uri[] = [];
  let codebaseRequested = false;

  for (const ref of references) {
    const refId = (ref.id ?? '').toLowerCase();
    console.log('[SafeChat] processing ref — id:', JSON.stringify(ref.id),
      'valueType:', ref.value === undefined ? 'undefined'
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
    console.log('[SafeChat] #codebase detected — workspaceFolders:',
      folders ? folders.map(f => f.uri.toString()) : 'undefined');
    if (folders) {
      for (const folder of folders) {
        uris.push(...await collectFiles(folder.uri));
      }
    } else {
      console.log('[SafeChat] WARNING: workspaceFolders is undefined — no files will be collected for #codebase');
    }
    console.log('[SafeChat] #codebase collected', uris.length, 'files');
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

  // Use a stable 'latest' directory — recreate to remove stale entries
  const latestDir = vscode.Uri.joinPath(baseUri, 'latest');
  try { await vscode.workspace.fs.delete(latestDir, { recursive: true }); } catch { /* first run */ }
  await vscode.workspace.fs.createDirectory(latestDir);

  // Write per-file original + masked pairs
  for (const file of maskedFiles) {
    const safeName = file.relPath.replace(/[/\\]/g, '_');
    await Promise.all([
      vscode.workspace.fs.writeFile(
        vscode.Uri.joinPath(latestDir, `${safeName}.original.txt`),
        Buffer.from(file.original, 'utf-8'),
      ),
      vscode.workspace.fs.writeFile(
        vscode.Uri.joinPath(latestDir, `${safeName}.masked.txt`),
        Buffer.from(file.masked, 'utf-8'),
      ),
    ]);
  }

  // Manifest listing all masked file paths
  await vscode.workspace.fs.writeFile(
    vscode.Uri.joinPath(latestDir, 'manifest.json'),
    Buffer.from(JSON.stringify(maskedFiles.map(f => f.relPath)), 'utf-8'),
  );

  latestCacheEntryUri = latestDir;
}

// ── Diff Viewer (per-file with QuickPick) ───────────────────────────────────

async function handleViewDiff(entryUriString?: string): Promise<void> {
  let entryUri: vscode.Uri | undefined;

  if (entryUriString) {
    entryUri = vscode.Uri.parse(entryUriString);
  } else {
    entryUri = latestCacheEntryUri;
    if (!entryUri) {
      // Try to recover from the stable 'latest' cache directory
      const baseUri = getCacheBaseUri();
      if (baseUri) {
        try {
          const latestDir = vscode.Uri.joinPath(baseUri, 'latest');
          await vscode.workspace.fs.stat(latestDir);
          entryUri = latestDir;
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
