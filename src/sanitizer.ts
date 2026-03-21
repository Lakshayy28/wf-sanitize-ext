import * as vscode from 'vscode';
import { spawn } from 'child_process';
import * as path from 'path';

// ────────────────────────────────────────────────────────────────────────────
// Presidio NLP bridge (Tier 1 — advanced PII masking)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Spawns the Presidio Python engine as a child process.
 * Sends `text` via stdin, collects anonymized output from stdout.
 *
 * Rejects if:
 *  - Python is not installed
 *  - Presidio dependencies are missing (exit code 2)
 *  - The process errors out for any other reason
 *
 * Prerequisites (remind developers):
 *   pip install presidio-analyzer presidio-anonymizer
 *   python -m spacy download en_core_web_lg
 */
function runPresidio(text: string, extensionPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(extensionPath, 'src', 'presidio_engine.py');

    // Resolve Python interpreter — prefer the bundled .venv, then system python3/python.
    const venvPython = path.join(
      extensionPath,
      '.venv',
      process.platform === 'win32' ? path.join('Scripts', 'python.exe') : path.join('bin', 'python')
    );
    const systemPython = process.platform === 'win32' ? 'python' : 'python3';
    const pythonBin = require('fs').existsSync(venvPython) ? venvPython : systemPython;

    const child = spawn(pythonBin, [scriptPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    child.on('error', (err: Error) => {
      // Typically "ENOENT" — python not found on PATH
      reject(new Error(`Failed to launch Python: ${err.message}`));
    });

    child.on('close', (code: number | null) => {
      if (code === 0) {
        resolve(stdout);
      } else if (code === 2) {
        // Special exit code from presidio_engine.py → Presidio not installed
        reject(new Error('Presidio is not installed on this machine.'));
      } else {
        reject(
          new Error(
            `Presidio process exited with code ${code}: ${stderr.trim()}`
          )
        );
      }
    });

    // Write the raw text to the child's stdin and close the stream.
    child.stdin.write(text);
    child.stdin.end();
  });
}

// ────────────────────────────────────────────────────────────────────────────
// Regex-based secret masking (Tier 2 — fallback)
// ────────────────────────────────────────────────────────────────────────────

/**
 * A robust regex that matches common secret patterns:
 *  - Keys like password, passwd, secret, api_key, apikey, api-key, token,
 *    access_token, auth_token, private_key, client_secret, credentials, etc.
 *  - Followed by an assignment operator ( = , : , := , => ) with optional quotes.
 *  - Captures the value portion (the actual secret).
 *
 * Also matches standalone patterns:
 *  - Bearer tokens:       Bearer <token>
 *  - AWS keys:            AKIA[0-9A-Z]{16}
 *  - Generic hex/base64:  long high-entropy strings following a key name
 */
const SECRET_KEY_REGEX = new RegExp(
  // ── Named-key = value patterns ───────────────────────────────────────
  '(' +
    // Key names (case-insensitive)
    '(?:password|passwd|pwd|secret|api_?key|api[-_]?secret|token|access_?token|' +
    'auth_?token|refresh_?token|private_?key|client_?secret|credentials|' +
    'database_?url|db_?password|connection_?string|encryption_?key|' +
    'jwt_?secret|session_?secret|signing_?key|bearer)' +
    // Assignment operators with optional surrounding whitespace
    '\\s*[:=]\\s*' +
    // Optional opening quote
    '["\']?' +
  ')' +
  // The actual secret value (captured group)
  '([^\\s"\'`;,}{\\]\\)]+)' +
  '|' +
  // ── Standalone patterns ──────────────────────────────────────────────
  // Bearer tokens in Authorization headers
  '(Bearer\\s+)([A-Za-z0-9\\-._~+\\/]+=*)' +
  '|' +
  // AWS Access Key IDs
  '(AKIA[0-9A-Z]{16})',
  'gi'
);

const MASK = '[MASKED_BY_SAFECHAT]';

/**
 * Sanitizes raw text by replacing detected secrets with a mask placeholder.
 * Returns the cleaned text and a flag indicating whether any replacements were made.
 */
export function regexSanitize(rawText: string): { cleanText: string; wasModified: boolean } {
  let wasModified = false;

  const cleanText = rawText.replace(SECRET_KEY_REGEX, (...args: string[]) => {
    wasModified = true;

    // Named-key = value  (groups 1, 2)
    if (args[1] && args[2]) {
      return args[1] + MASK;
    }
    // Bearer token        (groups 3, 4)
    if (args[3] && args[4]) {
      return args[3] + MASK;
    }
    // AWS key             (group 5)
    if (args[5]) {
      return MASK;
    }

    return MASK;
  });

  return { cleanText, wasModified };
}

// ────────────────────────────────────────────────────────────────────────────
// Cache directory helpers
// ────────────────────────────────────────────────────────────────────────────

function getCacheUri(): vscode.Uri | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return undefined;
  }
  return vscode.Uri.joinPath(folders[0].uri, '.vscode', '.temp_cache');
}

/**
 * Ensure the cache directory exists and contains a wildcard .gitignore
 * so the cached files are never accidentally committed.
 */
async function ensureCacheDir(cacheDir: vscode.Uri): Promise<void> {
  // createDirectory is idempotent — it won't throw if the dir already exists.
  await vscode.workspace.fs.createDirectory(cacheDir);

  const gitignoreUri = vscode.Uri.joinPath(cacheDir, '.gitignore');
  await vscode.workspace.fs.writeFile(
    gitignoreUri,
    Buffer.from('*\n', 'utf-8')
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize `rawText`, cache original + masked versions for diffing, and
 * return the clean text together with a modification flag.
 *
 * Strategy:
 *  1. Try Presidio (Tier 1) for NLP-based PII masking.
 *  2. If Presidio is unavailable, fall back to the regex engine (Tier 2).
 *  3. The regex pass always runs *after* Presidio to catch secrets that
 *     NLP alone might miss (e.g., `api_key=...` patterns).
 */
export async function sanitizeAndCache(
  rawText: string,
  extensionPath?: string
): Promise<{ cleanText: string; wasModified: boolean }> {
  let presidioText = rawText;
  let presidioModified = false;

  // ── Tier 1: Presidio NLP masking ───────────────────────────────────
  if (extensionPath) {
    try {
      presidioText = await runPresidio(rawText, extensionPath);
      presidioModified = presidioText !== rawText;
    } catch {
      // Presidio unavailable — continue with regex-only.
      // This is expected on machines without Python / Presidio.
    }
  }

  // ── Tier 2: Regex secret masking (always runs as a second pass) ────
  const { cleanText, wasModified: regexModified } = regexSanitize(presidioText);
  const wasModified = presidioModified || regexModified;

  if (wasModified) {
    const cacheDir = getCacheUri();
    if (cacheDir) {
      await ensureCacheDir(cacheDir);

      const originalUri = vscode.Uri.joinPath(cacheDir, 'original_context.txt');
      const maskedUri = vscode.Uri.joinPath(cacheDir, 'masked_context.txt');

      await Promise.all([
        vscode.workspace.fs.writeFile(originalUri, Buffer.from(rawText, 'utf-8')),
        vscode.workspace.fs.writeFile(maskedUri, Buffer.from(cleanText, 'utf-8')),
      ]);
    }
  }

  return { cleanText, wasModified };
}

/**
 * Opens the VS Code diff editor comparing the original and masked context files.
 * Bound to the `safecopilot.viewDiff` command.
 */
export async function viewDiffCommand(): Promise<void> {
  const cacheDir = getCacheUri();
  if (!cacheDir) {
    vscode.window.showWarningMessage(
      'SafeChat: No workspace folder found — cannot display diff.'
    );
    return;
  }

  const originalUri = vscode.Uri.joinPath(cacheDir, 'original_context.txt');
  const maskedUri = vscode.Uri.joinPath(cacheDir, 'masked_context.txt');

  try {
    // Quick existence check — will throw if the file doesn't exist.
    await vscode.workspace.fs.stat(originalUri);
    await vscode.workspace.fs.stat(maskedUri);
  } catch {
    vscode.window.showWarningMessage(
      'SafeChat: No cached diff available yet. Attach a file to @safechat first.'
    );
    return;
  }

  await vscode.commands.executeCommand(
    'vscode.diff',
    originalUri,
    maskedUri,
    'Original ↔ Sanitized Context'
  );
}
