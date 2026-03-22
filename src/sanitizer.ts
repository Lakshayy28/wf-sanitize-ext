import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';

// ────────────────────────────────────────────────────────────────────────────
// Presidio HTTP bridge (Tier 1 — advanced PII masking via local API server)
// ────────────────────────────────────────────────────────────────────────────

interface SanitizeResponse {
  sanitized_text: string;
  was_modified: boolean;
  entities_found: Array<{ entity_type: string; start: number; end: number; score: number }>;
}

/** Reads the configured Presidio server base URL from VS Code settings. */
function getPresidioApiUrl(): string {
  const config = vscode.workspace.getConfiguration('safechat');
  return (config.get<string>('presidioApiUrl') || 'http://localhost:8000').replace(/\/$/, '');
}

// ────────────────────────────────────────────────────────────────────────────
// Rules config (user-defined per-entity anonymization overrides)
// ────────────────────────────────────────────────────────────────────────────

/** Maps friendly alias names → canonical Presidio entity type strings. */
const ENTITY_ALIAS_MAP: Record<string, string> = {
  phonenumber:      'PHONE_NUMBER',
  phone:            'PHONE_NUMBER',
  accountnumber:    'US_BANK_NUMBER',
  bankaccount:      'US_BANK_NUMBER',
  email:            'EMAIL_ADDRESS',
  emailaddress:     'EMAIL_ADDRESS',
  emailaddr:        'EMAIL_ADDRESS',
  creditcard:       'CREDIT_CARD',
  cc:               'CREDIT_CARD',
  ssn:              'US_SSN',
  socialsecuritynumber: 'US_SSN',
  ipaddress:        'IP_ADDRESS',
  ip:               'IP_ADDRESS',
  person:           'PERSON',
  name:             'PERSON',
  url:              'URL',
  location:         'LOCATION',
  date:             'DATE_TIME',
  datetime:         'DATE_TIME',
  iban:             'IBAN_CODE',
  ibancode:         'IBAN_CODE',
  crypto:           'CRYPTO',
  bitcoin:          'CRYPTO',
  passport:         'US_PASSPORT',
  drivinglicense:   'US_DRIVER_LICENSE',
  driverslicense:   'US_DRIVER_LICENSE',
  medicallicense:   'MEDICAL_LICENSE',
  nrp:              'NRP',
};

/** Converts an alias or arbitrary casing to the canonical Presidio entity type. */
function normalizeEntityKey(key: string): string {
  const slug = key.toLowerCase().replace(/[_\s-]/g, '');
  return ENTITY_ALIAS_MAP[slug] ?? key.toUpperCase().replace(/[\s-]/g, '_');
}

/** Definition of a user-defined custom recognizer from the YAML config. */
export interface CustomRecognizerDef {
  name: string;
  pattern: string;
  score?: number;
  context?: string[];
}

/** Parsed result from the YAML config file. */
export interface RulesConfig {
  rules?: Record<string, string>;
  customRecognizers?: CustomRecognizerDef[];
  /** File extensions that are allowed for sanitization, e.g. [".yaml", ".json", ".env"]. */
  includeExtensions?: string[];
}

/**
 * Parses the subset of YAML needed for the rules file — no external deps.
 * Handles:
 *   rules:
 *     KeyName: Operation   # optional inline comment
 *   custom_recognizers:
 *     - name: EMPLOYEE_ID
 *       pattern: "EMP-\\d{6}"
 *       score: 0.85
 *       context:
 *         - employee
 *         - staff
 */
function parseRulesYaml(content: string): RulesConfig {
  const rules: Record<string, string> = {};
  const customRecognizers: CustomRecognizerDef[] = [];
  const includeExtensions: string[] = [];
  let section: 'none' | 'rules' | 'custom_recognizers' | 'custom_item' | 'custom_context'
             | 'include_extensions' = 'none';
  let currentItem: Partial<CustomRecognizerDef> = {};
  let currentContext: string[] = [];

  const flushItem = () => {
    if (currentItem.name && currentItem.pattern) {
      customRecognizers.push({
        name: currentItem.name,
        pattern: currentItem.pattern,
        score: currentItem.score ?? 0.85,
        context: currentContext.length > 0 ? currentContext : undefined,
      });
    }
    currentItem = {};
    currentContext = [];
  };

  for (const raw of content.split('\n')) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    const trimmed = line.trim();
    if (!trimmed) { continue; }

    // Top-level section headers
    if (trimmed === 'rules:')                { flushItem(); section = 'rules';               continue; }
    if (trimmed === 'custom_recognizers:')   { flushItem(); section = 'custom_recognizers';  continue; }
    if (trimmed === 'include_extensions:')   { flushItem(); section = 'include_extensions';  continue; }

    // Must be indented to be inside a section
    if (!/^\s/.test(line)) { flushItem(); section = 'none'; continue; }

    if (section === 'rules') {
      const m = trimmed.match(/^([A-Za-z0-9_]+)\s*:\s*([A-Za-z]+)/);
      if (m) { rules[m[1]] = m[2]; }
    }

    // Simple string-list sections
    if (section === 'include_extensions' && trimmed.startsWith('- ')) {
      const val = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
      if (val) { includeExtensions.push(val.startsWith('.') ? val.toLowerCase() : '.' + val.toLowerCase()); }
      continue;
    }


    if (section === 'custom_recognizers' || section === 'custom_item' || section === 'custom_context') {
      // New list item starts with "- name:"
      if (trimmed.startsWith('- ')) {
        flushItem();
        section = 'custom_item';
        const m = trimmed.match(/^-\s+name\s*:\s*(.+)/);
        if (m) { currentItem.name = m[1].trim().replace(/^["']|["']$/g, ''); }
        continue;
      }

      if (section === 'custom_context') {
        // Collect context list items
        if (trimmed.startsWith('- ')) {
          currentContext.push(trimmed.slice(2).trim().replace(/^["']|["']$/g, ''));
          continue;
        }
        // No longer in context list
        section = 'custom_item';
      }

      if (section === 'custom_item') {
        const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.*)/);
        if (kvMatch) {
          const key = kvMatch[1].toLowerCase();
          const val = kvMatch[2].trim().replace(/^["']|["']$/g, '');
          if (key === 'name') { currentItem.name = val; }
          else if (key === 'pattern') { currentItem.pattern = val; }
          else if (key === 'score') { currentItem.score = parseFloat(val) || 0.85; }
          else if (key === 'context') {
            // context can be inline [a, b] or a multi-line list
            if (val.startsWith('[')) {
              currentContext = val.replace(/[\[\]]/g, '').split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
            } else if (!val) {
              section = 'custom_context';
            }
          }
        }
      }
    }
  }
  flushItem();

  return {
    rules: Object.keys(rules).length > 0 ? rules : undefined,
    customRecognizers: customRecognizers.length > 0 ? customRecognizers : undefined,
    includeExtensions: includeExtensions.length > 0 ? includeExtensions : undefined,
  };
}

/**
 * Reads `.vscode/safechat-rules.yaml` (or the path from VS Code settings),
 * parses it, and returns the rules config including any custom recognizers.
 * Returns `undefined` if the file doesn't exist.
 */
export async function readRulesConfig(): Promise<RulesConfig | undefined> {
  const config = vscode.workspace.getConfiguration('safechat');
  const rulesPath = config.get<string>('rulesFile') || '.vscode/safechat-rules.yaml';
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) { return undefined; }
  const rulesUri = vscode.Uri.joinPath(folders[0].uri, rulesPath);
  try {
    const bytes = await vscode.workspace.fs.readFile(rulesUri);
    const parsed = parseRulesYaml(Buffer.from(bytes).toString('utf-8'));

    // Normalize rule keys to canonical Presidio entity types
    let normalizedRules: Record<string, string> | undefined;
    if (parsed.rules) {
      normalizedRules = {};
      for (const [k, v] of Object.entries(parsed.rules)) {
        normalizedRules[normalizeEntityKey(k)] = v;
      }
      if (Object.keys(normalizedRules).length === 0) { normalizedRules = undefined; }
    }

    return {
      rules: normalizedRules,
      customRecognizers: parsed.customRecognizers,
      includeExtensions: parsed.includeExtensions,
    };
  } catch {
    return undefined; // file absent or unreadable → use server defaults
  }
}

/**
 * Calls the `/sanitize` endpoint on the running Presidio HTTP server.
 * Rejects if the server is unreachable or returns a non-2xx status.
 */
function callPresidioApi(text: string, rulesConfig?: RulesConfig): Promise<SanitizeResponse> {
  return new Promise((resolve, reject) => {
    const baseUrl = getPresidioApiUrl();
    let urlObj: URL;
    try {
      urlObj = new URL('/sanitize', baseUrl);
    } catch {
      reject(new Error(`Invalid presidioApiUrl: ${baseUrl}`));
      return;
    }

    const payload: Record<string, unknown> = { text };
    if (rulesConfig?.rules && Object.keys(rulesConfig.rules).length > 0) {
      payload.rules = rulesConfig.rules;
    }
    if (rulesConfig?.customRecognizers && rulesConfig.customRecognizers.length > 0) {
      payload.custom_recognizers = rulesConfig.customRecognizers;
    }
    const body = JSON.stringify(payload);
    const options: http.RequestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const transport = urlObj.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data) as SanitizeResponse);
          } catch {
            reject(new Error(`Invalid JSON from Presidio server: ${data.slice(0, 200)}`));
          }
        } else {
          reject(new Error(`Presidio server returned HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on('error', (err: Error) => {
      reject(new Error(`Presidio server unreachable at ${baseUrl}: ${err.message}`));
    });

    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Presidio server request timed out after 10 s'));
    });

    req.write(body);
    req.end();
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

/**
 * In-memory pointer to the most recently written cache entry.
 * Used by viewDiffCommand so the button always opens the latest diff.
 */
let latestCacheEntryUri: vscode.Uri | undefined;

/** Returns the root `.vscode/.temp_cache` base directory URI. */
function getCacheBaseUri(): vscode.Uri | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return undefined;
  }
  return vscode.Uri.joinPath(folders[0].uri, '.vscode', '.temp_cache');
}

/**
 * Generates a filesystem-safe timestamp string for use as a subfolder name.
 * e.g. "2026-03-21_10-30-00-042"
 */
function timestampSlug(): string {
  const now = new Date();
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return (
    `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
    `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}` +
    `-${pad(now.getMilliseconds(), 3)}`
  );
}

/**
 * Ensures the base cache root exists and contains a wildcard .gitignore.
 * Only writes the .gitignore once (cheap stat-check first).
 */
async function ensureCacheRoot(baseUri: vscode.Uri): Promise<void> {
  await vscode.workspace.fs.createDirectory(baseUri);

  const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
  try {
    await vscode.workspace.fs.stat(gitignoreUri);
  } catch {
    // Doesn't exist yet — create it.
    await vscode.workspace.fs.writeFile(
      gitignoreUri,
      Buffer.from('*\n', 'utf-8')
    );
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize text without writing any cache files.
 * Used by the per-file sanitization pipeline in extension.ts.
 *
 * Strategy:
 *  1. Try Presidio (Tier 1) for NLP-based PII masking.
 *  2. If Presidio is unavailable, fall back to the regex engine (Tier 2).
 *  3. The regex pass always runs *after* Presidio to catch secrets that
 *     NLP alone might miss (e.g., `api_key=...` patterns).
 */
export async function sanitizeOnly(
  rawText: string,
  rulesConfig?: RulesConfig,
): Promise<{
  cleanText: string;
  wasModified: boolean;
  presidioError?: string;
}> {
  let presidioText = rawText;
  let presidioModified = false;
  let presidioError: string | undefined;

  try {
    const result = await callPresidioApi(rawText, rulesConfig);
    presidioText = result.sanitized_text;
    presidioModified = result.was_modified;
  } catch (err) {
    presidioError = err instanceof Error ? err.message : String(err);
  }

  const { cleanText, wasModified: regexModified } = regexSanitize(presidioText);
  const wasModified = presidioModified || regexModified;

  return { cleanText, wasModified, presidioError };
}

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
  _extensionPath?: string
): Promise<{
  cleanText: string;
  wasModified: boolean;
  cacheEntryUri?: vscode.Uri;
  presidioError?: string;
}> {
  let presidioText = rawText;
  let presidioModified = false;
  let presidioError: string | undefined;

  // ── Tier 1: Presidio API masking ────────────────────────────────────
  const rulesConfig = await readRulesConfig();
  try {
    const result = await callPresidioApi(rawText, rulesConfig);
    presidioText = result.sanitized_text;
    presidioModified = result.was_modified;
  } catch (err) {
    // Server unreachable or returned an error — fall back to regex.
    presidioError = err instanceof Error ? err.message : String(err);
  }

  // ── Tier 2: Regex secret masking (always runs as a second pass) ────
  const { cleanText, wasModified: regexModified } = regexSanitize(presidioText);
  const wasModified = presidioModified || regexModified;

  if (wasModified) {
    const baseUri = getCacheBaseUri();
    if (baseUri) {
      await ensureCacheRoot(baseUri);

      // Each prompt gets its own timestamped subfolder — previous diffs are
      // never overwritten and remain on disk for manual inspection.
      const entryDir = vscode.Uri.joinPath(baseUri, timestampSlug());
      await vscode.workspace.fs.createDirectory(entryDir);

      const originalUri = vscode.Uri.joinPath(entryDir, 'original_context.txt');
      const maskedUri   = vscode.Uri.joinPath(entryDir, 'masked_context.txt');

      await Promise.all([
        vscode.workspace.fs.writeFile(originalUri, Buffer.from(rawText, 'utf-8')),
        vscode.workspace.fs.writeFile(maskedUri, Buffer.from(cleanText, 'utf-8')),
      ]);

      // Update the in-memory pointer so the command-palette fallback works
      // after an extension reload (no button argument available then).
      latestCacheEntryUri = entryDir;

      return { cleanText, wasModified, cacheEntryUri: entryDir, presidioError };
    }
  }

  return { cleanText, wasModified, presidioError };
}

/**
 * Opens the VS Code diff editor comparing the original and masked context files.
 * Bound to the `safecopilot.viewDiff` command.
 */
export async function viewDiffCommand(entryUriString?: string): Promise<void> {
  // If the button passed a specific entry URI, use it directly.
  // This ensures each chat button always opens its own prompt's diff,
  // regardless of how many prompts have run since.
  if (entryUriString) {
    const entryUri = vscode.Uri.parse(entryUriString);
    const originalUri = vscode.Uri.joinPath(entryUri, 'original_context.txt');
    const maskedUri   = vscode.Uri.joinPath(entryUri, 'masked_context.txt');
    await vscode.commands.executeCommand(
      'vscode.diff',
      originalUri,
      maskedUri,
      `Original ↔ Sanitized  [${entryUri.path.split('/').pop()}]`
    );
    return;
  }

  // Fallback path: command palette invocation (no argument) — recover
  // the most recent entry from memory or disk.
  if (!latestCacheEntryUri) {
    // No in-memory pointer — extension may have reloaded. Try to recover the
    // most recent timestamped subfolder from disk.
    const baseUri = getCacheBaseUri();
    if (baseUri) {
      try {
        const entries = await vscode.workspace.fs.readDirectory(baseUri);
        const dirs = entries
          .filter(([, type]) => type === vscode.FileType.Directory)
          .map(([name]) => name)
          .sort() // ISO timestamps sort lexicographically = chronologically
          .reverse();
        if (dirs.length > 0) {
          latestCacheEntryUri = vscode.Uri.joinPath(baseUri, dirs[0]);
        }
      } catch {
        // base dir not created yet — fall through to the warning below.
      }
    }
  }

  if (!latestCacheEntryUri) {
    vscode.window.showWarningMessage(
      'SafeChat: No cached diff available yet. Attach a file to @safechat first.'
    );
    return;
  }

  const originalUri = vscode.Uri.joinPath(latestCacheEntryUri, 'original_context.txt');
  const maskedUri   = vscode.Uri.joinPath(latestCacheEntryUri, 'masked_context.txt');

  await vscode.commands.executeCommand(
    'vscode.diff',
    originalUri,
    maskedUri,
    `Original ↔ Sanitized  [${latestCacheEntryUri.path.split('/').pop()}]`
  );
}
